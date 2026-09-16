rule TTP_XOR_MULT_DOSStub_21eb {
  strings:
    $key_21eb = { 75 83 [2] 01 9b [2] 46 99 [2] 01 88 [2] 4f 84 [2] 43 8e [2] 54 85 [2] 4f cb [2] 72 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_17eb {
  strings:
    $key_17eb = { 43 83 [2] 37 9b [2] 70 99 [2] 37 88 [2] 79 84 [2] 75 8e [2] 62 85 [2] 79 cb [2] 44 }

  condition:
    any of them
}
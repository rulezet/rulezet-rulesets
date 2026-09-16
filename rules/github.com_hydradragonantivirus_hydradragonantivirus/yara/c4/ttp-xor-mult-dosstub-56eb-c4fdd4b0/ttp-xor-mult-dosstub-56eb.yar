rule TTP_XOR_MULT_DOSStub_56eb {
  strings:
    $key_56eb = { 02 83 [2] 76 9b [2] 31 99 [2] 76 88 [2] 38 84 [2] 34 8e [2] 23 85 [2] 38 cb [2] 05 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_6217 {
  strings:
    $key_6217 = { 36 7f [2] 42 67 [2] 05 65 [2] 42 74 [2] 0c 78 [2] 00 72 [2] 17 79 [2] 0c 37 [2] 31 }

  condition:
    any of them
}
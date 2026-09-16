rule TTP_XOR_MULT_DOSStub_6817 {
  strings:
    $key_6817 = { 3c 7f [2] 48 67 [2] 0f 65 [2] 48 74 [2] 06 78 [2] 0a 72 [2] 1d 79 [2] 06 37 [2] 3b }

  condition:
    any of them
}
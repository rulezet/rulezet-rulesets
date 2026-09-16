rule TTP_XOR_MULT_DOSStub_4817 {
  strings:
    $key_4817 = { 1c 7f [2] 68 67 [2] 2f 65 [2] 68 74 [2] 26 78 [2] 2a 72 [2] 3d 79 [2] 26 37 [2] 1b }

  condition:
    any of them
}
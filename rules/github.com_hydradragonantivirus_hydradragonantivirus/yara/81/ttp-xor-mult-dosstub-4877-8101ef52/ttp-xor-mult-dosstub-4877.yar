rule TTP_XOR_MULT_DOSStub_4877 {
  strings:
    $key_4877 = { 1c 1f [2] 68 07 [2] 2f 05 [2] 68 14 [2] 26 18 [2] 2a 12 [2] 3d 19 [2] 26 57 [2] 1b }

  condition:
    any of them
}
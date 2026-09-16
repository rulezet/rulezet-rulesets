rule TTP_XOR_MULT_DOSStub_4870 {
  strings:
    $key_4870 = { 1c 18 [2] 68 00 [2] 2f 02 [2] 68 13 [2] 26 1f [2] 2a 15 [2] 3d 1e [2] 26 50 [2] 1b }

  condition:
    any of them
}
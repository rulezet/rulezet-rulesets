rule TTP_XOR_MULT_DOSStub_4876 {
  strings:
    $key_4876 = { 1c 1e [2] 68 06 [2] 2f 04 [2] 68 15 [2] 26 19 [2] 2a 13 [2] 3d 18 [2] 26 56 [2] 1b }

  condition:
    any of them
}
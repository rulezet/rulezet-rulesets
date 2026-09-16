rule TTP_XOR_MULT_DOSStub_4810 {
  strings:
    $key_4810 = { 1c 78 [2] 68 60 [2] 2f 62 [2] 68 73 [2] 26 7f [2] 2a 75 [2] 3d 7e [2] 26 30 [2] 1b }

  condition:
    any of them
}
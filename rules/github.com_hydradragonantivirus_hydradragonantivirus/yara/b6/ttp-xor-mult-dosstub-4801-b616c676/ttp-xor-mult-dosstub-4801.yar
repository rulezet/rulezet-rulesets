rule TTP_XOR_MULT_DOSStub_4801 {
  strings:
    $key_4801 = { 1c 69 [2] 68 71 [2] 2f 73 [2] 68 62 [2] 26 6e [2] 2a 64 [2] 3d 6f [2] 26 21 [2] 1b }

  condition:
    any of them
}
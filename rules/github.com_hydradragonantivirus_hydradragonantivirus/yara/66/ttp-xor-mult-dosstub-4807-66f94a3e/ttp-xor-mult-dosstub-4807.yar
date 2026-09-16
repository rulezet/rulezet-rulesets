rule TTP_XOR_MULT_DOSStub_4807 {
  strings:
    $key_4807 = { 1c 6f [2] 68 77 [2] 2f 75 [2] 68 64 [2] 26 68 [2] 2a 62 [2] 3d 69 [2] 26 27 [2] 1b }

  condition:
    any of them
}
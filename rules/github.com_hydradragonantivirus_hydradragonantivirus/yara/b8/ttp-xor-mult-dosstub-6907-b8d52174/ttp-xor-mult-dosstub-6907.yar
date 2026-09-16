rule TTP_XOR_MULT_DOSStub_6907 {
  strings:
    $key_6907 = { 3d 6f [2] 49 77 [2] 0e 75 [2] 49 64 [2] 07 68 [2] 0b 62 [2] 1c 69 [2] 07 27 [2] 3a }

  condition:
    any of them
}
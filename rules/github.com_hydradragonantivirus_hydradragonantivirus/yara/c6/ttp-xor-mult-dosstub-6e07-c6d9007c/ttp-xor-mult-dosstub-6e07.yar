rule TTP_XOR_MULT_DOSStub_6e07 {
  strings:
    $key_6e07 = { 3a 6f [2] 4e 77 [2] 09 75 [2] 4e 64 [2] 00 68 [2] 0c 62 [2] 1b 69 [2] 00 27 [2] 3d }

  condition:
    any of them
}
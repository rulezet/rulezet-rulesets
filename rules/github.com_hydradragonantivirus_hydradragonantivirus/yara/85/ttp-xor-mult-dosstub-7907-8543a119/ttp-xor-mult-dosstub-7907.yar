rule TTP_XOR_MULT_DOSStub_7907 {
  strings:
    $key_7907 = { 2d 6f [2] 59 77 [2] 1e 75 [2] 59 64 [2] 17 68 [2] 1b 62 [2] 0c 69 [2] 17 27 [2] 2a }

  condition:
    any of them
}
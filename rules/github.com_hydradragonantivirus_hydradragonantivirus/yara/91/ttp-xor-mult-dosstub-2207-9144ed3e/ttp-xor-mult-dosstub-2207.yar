rule TTP_XOR_MULT_DOSStub_2207 {
  strings:
    $key_2207 = { 76 6f [2] 02 77 [2] 45 75 [2] 02 64 [2] 4c 68 [2] 40 62 [2] 57 69 [2] 4c 27 [2] 71 }

  condition:
    any of them
}
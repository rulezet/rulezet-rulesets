rule TTP_XOR_MULT_DOSStub_7007 {
  strings:
    $key_7007 = { 24 6f [2] 50 77 [2] 17 75 [2] 50 64 [2] 1e 68 [2] 12 62 [2] 05 69 [2] 1e 27 [2] 23 }

  condition:
    any of them
}
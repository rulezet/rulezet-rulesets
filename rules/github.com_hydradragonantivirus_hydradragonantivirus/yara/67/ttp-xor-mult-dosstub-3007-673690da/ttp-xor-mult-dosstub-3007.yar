rule TTP_XOR_MULT_DOSStub_3007 {
  strings:
    $key_3007 = { 64 6f [2] 10 77 [2] 57 75 [2] 10 64 [2] 5e 68 [2] 52 62 [2] 45 69 [2] 5e 27 [2] 63 }

  condition:
    any of them
}
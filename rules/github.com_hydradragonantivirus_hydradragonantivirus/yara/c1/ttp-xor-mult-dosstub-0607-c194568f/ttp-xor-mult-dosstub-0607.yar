rule TTP_XOR_MULT_DOSStub_0607 {
  strings:
    $key_0607 = { 52 6f [2] 26 77 [2] 61 75 [2] 26 64 [2] 68 68 [2] 64 62 [2] 73 69 [2] 68 27 [2] 55 }

  condition:
    any of them
}
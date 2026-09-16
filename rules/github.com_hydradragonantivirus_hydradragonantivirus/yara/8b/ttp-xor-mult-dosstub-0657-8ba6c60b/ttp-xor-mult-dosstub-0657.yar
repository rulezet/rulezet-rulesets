rule TTP_XOR_MULT_DOSStub_0657 {
  strings:
    $key_0657 = { 52 3f [2] 26 27 [2] 61 25 [2] 26 34 [2] 68 38 [2] 64 32 [2] 73 39 [2] 68 77 [2] 55 }

  condition:
    any of them
}
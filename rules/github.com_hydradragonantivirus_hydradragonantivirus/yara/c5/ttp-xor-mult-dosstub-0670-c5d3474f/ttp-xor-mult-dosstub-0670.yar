rule TTP_XOR_MULT_DOSStub_0670 {
  strings:
    $key_0670 = { 52 18 [2] 26 00 [2] 61 02 [2] 26 13 [2] 68 1f [2] 64 15 [2] 73 1e [2] 68 50 [2] 55 }

  condition:
    any of them
}
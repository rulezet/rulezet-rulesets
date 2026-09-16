rule TTP_XOR_MULT_DOSStub_0630 {
  strings:
    $key_0630 = { 52 58 [2] 26 40 [2] 61 42 [2] 26 53 [2] 68 5f [2] 64 55 [2] 73 5e [2] 68 10 [2] 55 }

  condition:
    any of them
}
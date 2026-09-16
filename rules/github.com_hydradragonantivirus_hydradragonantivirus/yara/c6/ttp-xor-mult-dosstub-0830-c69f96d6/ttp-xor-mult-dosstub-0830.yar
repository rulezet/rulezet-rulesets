rule TTP_XOR_MULT_DOSStub_0830 {
  strings:
    $key_0830 = { 5c 58 [2] 28 40 [2] 6f 42 [2] 28 53 [2] 66 5f [2] 6a 55 [2] 7d 5e [2] 66 10 [2] 5b }

  condition:
    any of them
}
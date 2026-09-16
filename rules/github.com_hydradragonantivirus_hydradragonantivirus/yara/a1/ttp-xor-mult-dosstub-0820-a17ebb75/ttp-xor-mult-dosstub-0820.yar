rule TTP_XOR_MULT_DOSStub_0820 {
  strings:
    $key_0820 = { 5c 48 [2] 28 50 [2] 6f 52 [2] 28 43 [2] 66 4f [2] 6a 45 [2] 7d 4e [2] 66 00 [2] 5b }

  condition:
    any of them
}
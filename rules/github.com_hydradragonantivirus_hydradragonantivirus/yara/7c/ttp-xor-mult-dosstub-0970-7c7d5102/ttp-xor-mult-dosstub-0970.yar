rule TTP_XOR_MULT_DOSStub_0970 {
  strings:
    $key_0970 = { 5d 18 [2] 29 00 [2] 6e 02 [2] 29 13 [2] 67 1f [2] 6b 15 [2] 7c 1e [2] 67 50 [2] 5a }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_0f40 {
  strings:
    $key_0f40 = { 5b 28 [2] 2f 30 [2] 68 32 [2] 2f 23 [2] 61 2f [2] 6d 25 [2] 7a 2e [2] 61 60 [2] 5c }

  condition:
    any of them
}
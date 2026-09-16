rule TTP_XOR_MULT_DOSStub_30e7 {
  strings:
    $key_30e7 = { 64 8f [2] 10 97 [2] 57 95 [2] 10 84 [2] 5e 88 [2] 52 82 [2] 45 89 [2] 5e c7 [2] 63 }

  condition:
    any of them
}
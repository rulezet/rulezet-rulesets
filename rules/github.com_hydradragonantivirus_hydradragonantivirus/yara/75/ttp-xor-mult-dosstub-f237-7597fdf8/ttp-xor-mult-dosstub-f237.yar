rule TTP_XOR_MULT_DOSStub_f237 {
  strings:
    $key_f237 = { a6 5f [2] d2 47 [2] 95 45 [2] d2 54 [2] 9c 58 [2] 90 52 [2] 87 59 [2] 9c 17 [2] a1 }

  condition:
    any of them
}
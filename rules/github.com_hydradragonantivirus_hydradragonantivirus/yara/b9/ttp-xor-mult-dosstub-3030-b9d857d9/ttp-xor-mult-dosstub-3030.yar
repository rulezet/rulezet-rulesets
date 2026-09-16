rule TTP_XOR_MULT_DOSStub_3030 {
  strings:
    $key_3030 = { 64 58 [2] 10 40 [2] 57 42 [2] 10 53 [2] 5e 5f [2] 52 55 [2] 45 5e [2] 5e 10 [2] 63 }

  condition:
    any of them
}
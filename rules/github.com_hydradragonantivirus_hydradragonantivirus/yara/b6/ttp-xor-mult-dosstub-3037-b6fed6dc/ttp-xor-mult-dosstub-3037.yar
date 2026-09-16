rule TTP_XOR_MULT_DOSStub_3037 {
  strings:
    $key_3037 = { 64 5f [2] 10 47 [2] 57 45 [2] 10 54 [2] 5e 58 [2] 52 52 [2] 45 59 [2] 5e 17 [2] 63 }

  condition:
    any of them
}
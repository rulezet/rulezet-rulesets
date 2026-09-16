rule TTP_XOR_MULT_DOSStub_29d2 {
  strings:
    $key_29d2 = { 7d ba [2] 09 a2 [2] 4e a0 [2] 09 b1 [2] 47 bd [2] 4b b7 [2] 5c bc [2] 47 f2 [2] 7a }

  condition:
    any of them
}
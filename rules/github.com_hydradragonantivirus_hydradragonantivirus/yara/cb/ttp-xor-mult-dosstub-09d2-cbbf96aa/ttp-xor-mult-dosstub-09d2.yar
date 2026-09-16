rule TTP_XOR_MULT_DOSStub_09d2 {
  strings:
    $key_09d2 = { 5d ba [2] 29 a2 [2] 6e a0 [2] 29 b1 [2] 67 bd [2] 6b b7 [2] 7c bc [2] 67 f2 [2] 5a }

  condition:
    any of them
}
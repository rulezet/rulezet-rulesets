rule TTP_XOR_MULT_DOSStub_2bd2 {
  strings:
    $key_2bd2 = { 7f ba [2] 0b a2 [2] 4c a0 [2] 0b b1 [2] 45 bd [2] 49 b7 [2] 5e bc [2] 45 f2 [2] 78 }

  condition:
    any of them
}
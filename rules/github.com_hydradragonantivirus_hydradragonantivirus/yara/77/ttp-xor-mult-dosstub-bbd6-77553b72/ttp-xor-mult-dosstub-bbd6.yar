rule TTP_XOR_MULT_DOSStub_bbd6 {
  strings:
    $key_bbd6 = { ef be [2] 9b a6 [2] dc a4 [2] 9b b5 [2] d5 b9 [2] d9 b3 [2] ce b8 [2] d5 f6 [2] e8 }

  condition:
    any of them
}
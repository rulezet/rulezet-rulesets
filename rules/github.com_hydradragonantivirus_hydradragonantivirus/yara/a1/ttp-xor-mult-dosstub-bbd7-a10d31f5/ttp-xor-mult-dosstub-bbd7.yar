rule TTP_XOR_MULT_DOSStub_bbd7 {
  strings:
    $key_bbd7 = { ef bf [2] 9b a7 [2] dc a5 [2] 9b b4 [2] d5 b8 [2] d9 b2 [2] ce b9 [2] d5 f7 [2] e8 }

  condition:
    any of them
}
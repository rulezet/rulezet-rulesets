rule TTP_XOR_MULT_DOSStub_bb89 {
  strings:
    $key_bb89 = { ef e1 [2] 9b f9 [2] dc fb [2] 9b ea [2] d5 e6 [2] d9 ec [2] ce e7 [2] d5 a9 [2] e8 }

  condition:
    any of them
}
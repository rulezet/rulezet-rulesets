rule TTP_XOR_MULT_DOSStub_bb88 {
  strings:
    $key_bb88 = { ef e0 [2] 9b f8 [2] dc fa [2] 9b eb [2] d5 e7 [2] d9 ed [2] ce e6 [2] d5 a8 [2] e8 }

  condition:
    any of them
}
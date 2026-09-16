rule TTP_XOR_MULT_DOSStub_bb86 {
  strings:
    $key_bb86 = { ef ee [2] 9b f6 [2] dc f4 [2] 9b e5 [2] d5 e9 [2] d9 e3 [2] ce e8 [2] d5 a6 [2] e8 }

  condition:
    any of them
}
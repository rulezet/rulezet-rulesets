rule TTP_XOR_MULT_DOSStub_bb83 {
  strings:
    $key_bb83 = { ef eb [2] 9b f3 [2] dc f1 [2] 9b e0 [2] d5 ec [2] d9 e6 [2] ce ed [2] d5 a3 [2] e8 }

  condition:
    any of them
}
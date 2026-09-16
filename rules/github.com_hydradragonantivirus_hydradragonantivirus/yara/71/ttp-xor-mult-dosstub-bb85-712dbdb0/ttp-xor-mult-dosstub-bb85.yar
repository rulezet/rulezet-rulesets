rule TTP_XOR_MULT_DOSStub_bb85 {
  strings:
    $key_bb85 = { ef ed [2] 9b f5 [2] dc f7 [2] 9b e6 [2] d5 ea [2] d9 e0 [2] ce eb [2] d5 a5 [2] e8 }

  condition:
    any of them
}
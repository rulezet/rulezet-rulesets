rule TTP_XOR_MULT_DOSStub_bb9a {
  strings:
    $key_bb9a = { ef f2 [2] 9b ea [2] dc e8 [2] 9b f9 [2] d5 f5 [2] d9 ff [2] ce f4 [2] d5 ba [2] e8 }

  condition:
    any of them
}
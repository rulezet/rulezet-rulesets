rule TTP_XOR_MULT_DOSStub_bb96 {
  strings:
    $key_bb96 = { ef fe [2] 9b e6 [2] dc e4 [2] 9b f5 [2] d5 f9 [2] d9 f3 [2] ce f8 [2] d5 b6 [2] e8 }

  condition:
    any of them
}
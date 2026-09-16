rule TTP_XOR_MULT_DOSStub_bb81 {
  strings:
    $key_bb81 = { ef e9 [2] 9b f1 [2] dc f3 [2] 9b e2 [2] d5 ee [2] d9 e4 [2] ce ef [2] d5 a1 [2] e8 }

  condition:
    any of them
}
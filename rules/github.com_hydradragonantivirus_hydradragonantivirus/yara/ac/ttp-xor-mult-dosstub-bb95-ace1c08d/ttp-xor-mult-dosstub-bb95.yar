rule TTP_XOR_MULT_DOSStub_bb95 {
  strings:
    $key_bb95 = { ef fd [2] 9b e5 [2] dc e7 [2] 9b f6 [2] d5 fa [2] d9 f0 [2] ce fb [2] d5 b5 [2] e8 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_8e95 {
  strings:
    $key_8e95 = { da fd [2] ae e5 [2] e9 e7 [2] ae f6 [2] e0 fa [2] ec f0 [2] fb fb [2] e0 b5 [2] dd }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_b299 {
  strings:
    $key_b299 = { e6 f1 [2] 92 e9 [2] d5 eb [2] 92 fa [2] dc f6 [2] d0 fc [2] c7 f7 [2] dc b9 [2] e1 }

  condition:
    any of them
}
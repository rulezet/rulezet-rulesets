rule TTP_XOR_MULT_DOSStub_fab2 {
  strings:
    $key_fab2 = { ae da [2] da c2 [2] 9d c0 [2] da d1 [2] 94 dd [2] 98 d7 [2] 8f dc [2] 94 92 [2] a9 }

  condition:
    any of them
}
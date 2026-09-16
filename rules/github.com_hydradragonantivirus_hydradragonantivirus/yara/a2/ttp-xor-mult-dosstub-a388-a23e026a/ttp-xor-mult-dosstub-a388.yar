rule TTP_XOR_MULT_DOSStub_a388 {
  strings:
    $key_a388 = { f7 e0 [2] 83 f8 [2] c4 fa [2] 83 eb [2] cd e7 [2] c1 ed [2] d6 e6 [2] cd a8 [2] f0 }

  condition:
    any of them
}
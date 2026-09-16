rule TTP_XOR_MULT_DOSStub_e199 {
  strings:
    $key_e199 = { b5 f1 [2] c1 e9 [2] 86 eb [2] c1 fa [2] 8f f6 [2] 83 fc [2] 94 f7 [2] 8f b9 [2] b2 }

  condition:
    any of them
}
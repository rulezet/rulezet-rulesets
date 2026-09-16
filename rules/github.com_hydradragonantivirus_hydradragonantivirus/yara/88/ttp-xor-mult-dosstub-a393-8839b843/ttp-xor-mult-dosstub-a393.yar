rule TTP_XOR_MULT_DOSStub_a393 {
  strings:
    $key_a393 = { f7 fb [2] 83 e3 [2] c4 e1 [2] 83 f0 [2] cd fc [2] c1 f6 [2] d6 fd [2] cd b3 [2] f0 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_a299 {
  strings:
    $key_a299 = { f6 f1 [2] 82 e9 [2] c5 eb [2] 82 fa [2] cc f6 [2] c0 fc [2] d7 f7 [2] cc b9 [2] f1 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_a199 {
  strings:
    $key_a199 = { f5 f1 [2] 81 e9 [2] c6 eb [2] 81 fa [2] cf f6 [2] c3 fc [2] d4 f7 [2] cf b9 [2] f2 }

  condition:
    any of them
}
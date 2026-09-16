rule TTP_XOR_MULT_DOSStub_a099 {
  strings:
    $key_a099 = { f4 f1 [2] 80 e9 [2] c7 eb [2] 80 fa [2] ce f6 [2] c2 fc [2] d5 f7 [2] ce b9 [2] f3 }

  condition:
    any of them
}
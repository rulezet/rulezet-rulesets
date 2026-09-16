rule TTP_XOR_MULT_DOSStub_9499 {
  strings:
    $key_9499 = { c0 f1 [2] b4 e9 [2] f3 eb [2] b4 fa [2] fa f6 [2] f6 fc [2] e1 f7 [2] fa b9 [2] c7 }

  condition:
    any of them
}
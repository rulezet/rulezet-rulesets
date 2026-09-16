rule TTP_XOR_MULT_DOSStub_8299 {
  strings:
    $key_8299 = { d6 f1 [2] a2 e9 [2] e5 eb [2] a2 fa [2] ec f6 [2] e0 fc [2] f7 f7 [2] ec b9 [2] d1 }

  condition:
    any of them
}
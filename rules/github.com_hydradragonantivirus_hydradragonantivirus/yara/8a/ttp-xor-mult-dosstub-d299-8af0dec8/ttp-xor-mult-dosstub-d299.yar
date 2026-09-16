rule TTP_XOR_MULT_DOSStub_d299 {
  strings:
    $key_d299 = { 86 f1 [2] f2 e9 [2] b5 eb [2] f2 fa [2] bc f6 [2] b0 fc [2] a7 f7 [2] bc b9 [2] 81 }

  condition:
    any of them
}
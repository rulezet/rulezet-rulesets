rule TTP_XOR_MULT_DOSStub_ab94 {
  strings:
    $key_ab94 = { ff fc [2] 8b e4 [2] cc e6 [2] 8b f7 [2] c5 fb [2] c9 f1 [2] de fa [2] c5 b4 [2] f8 }

  condition:
    any of them
}
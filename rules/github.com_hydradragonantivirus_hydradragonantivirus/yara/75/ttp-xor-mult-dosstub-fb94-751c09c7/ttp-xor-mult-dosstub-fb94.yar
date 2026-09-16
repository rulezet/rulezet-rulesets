rule TTP_XOR_MULT_DOSStub_fb94 {
  strings:
    $key_fb94 = { af fc [2] db e4 [2] 9c e6 [2] db f7 [2] 95 fb [2] 99 f1 [2] 8e fa [2] 95 b4 [2] a8 }

  condition:
    any of them
}
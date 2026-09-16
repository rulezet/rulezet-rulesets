rule TTP_XOR_MULT_DOSStub_db94 {
  strings:
    $key_db94 = { 8f fc [2] fb e4 [2] bc e6 [2] fb f7 [2] b5 fb [2] b9 f1 [2] ae fa [2] b5 b4 [2] 88 }

  condition:
    any of them
}
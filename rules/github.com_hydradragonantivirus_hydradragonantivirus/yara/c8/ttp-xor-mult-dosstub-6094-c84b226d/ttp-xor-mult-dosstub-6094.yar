rule TTP_XOR_MULT_DOSStub_6094 {
  strings:
    $key_6094 = { 34 fc [2] 40 e4 [2] 07 e6 [2] 40 f7 [2] 0e fb [2] 02 f1 [2] 15 fa [2] 0e b4 [2] 33 }

  condition:
    any of them
}
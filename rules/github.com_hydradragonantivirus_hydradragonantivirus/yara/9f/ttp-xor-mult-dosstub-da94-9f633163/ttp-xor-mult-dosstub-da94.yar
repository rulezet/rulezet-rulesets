rule TTP_XOR_MULT_DOSStub_da94 {
  strings:
    $key_da94 = { 8e fc [2] fa e4 [2] bd e6 [2] fa f7 [2] b4 fb [2] b8 f1 [2] af fa [2] b4 b4 [2] 89 }

  condition:
    any of them
}
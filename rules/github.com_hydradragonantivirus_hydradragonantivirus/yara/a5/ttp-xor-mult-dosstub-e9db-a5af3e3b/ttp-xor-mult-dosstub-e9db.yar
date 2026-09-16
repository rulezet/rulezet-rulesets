rule TTP_XOR_MULT_DOSStub_e9db {
  strings:
    $key_e9db = { bd b3 [2] c9 ab [2] 8e a9 [2] c9 b8 [2] 87 b4 [2] 8b be [2] 9c b5 [2] 87 fb [2] ba }

  condition:
    any of them
}
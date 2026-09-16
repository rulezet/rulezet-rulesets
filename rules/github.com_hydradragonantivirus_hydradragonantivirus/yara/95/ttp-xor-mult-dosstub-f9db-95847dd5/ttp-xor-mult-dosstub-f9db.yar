rule TTP_XOR_MULT_DOSStub_f9db {
  strings:
    $key_f9db = { ad b3 [2] d9 ab [2] 9e a9 [2] d9 b8 [2] 97 b4 [2] 9b be [2] 8c b5 [2] 97 fb [2] aa }

  condition:
    any of them
}
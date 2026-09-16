rule TTP_XOR_MULT_DOSStub_d9db {
  strings:
    $key_d9db = { 8d b3 [2] f9 ab [2] be a9 [2] f9 b8 [2] b7 b4 [2] bb be [2] ac b5 [2] b7 fb [2] 8a }

  condition:
    any of them
}
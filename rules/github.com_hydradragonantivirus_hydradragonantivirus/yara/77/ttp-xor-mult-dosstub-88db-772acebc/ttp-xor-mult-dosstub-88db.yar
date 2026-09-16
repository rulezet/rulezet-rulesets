rule TTP_XOR_MULT_DOSStub_88db {
  strings:
    $key_88db = { dc b3 [2] a8 ab [2] ef a9 [2] a8 b8 [2] e6 b4 [2] ea be [2] fd b5 [2] e6 fb [2] db }

  condition:
    any of them
}
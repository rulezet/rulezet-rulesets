rule TTP_XOR_MULT_DOSStub_fddb {
  strings:
    $key_fddb = { a9 b3 [2] dd ab [2] 9a a9 [2] dd b8 [2] 93 b4 [2] 9f be [2] 88 b5 [2] 93 fb [2] ae }

  condition:
    any of them
}
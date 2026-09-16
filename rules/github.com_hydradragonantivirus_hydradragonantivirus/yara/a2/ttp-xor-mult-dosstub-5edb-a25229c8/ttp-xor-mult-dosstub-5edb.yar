rule TTP_XOR_MULT_DOSStub_5edb {
  strings:
    $key_5edb = { 0a b3 [2] 7e ab [2] 39 a9 [2] 7e b8 [2] 30 b4 [2] 3c be [2] 2b b5 [2] 30 fb [2] 0d }

  condition:
    any of them
}
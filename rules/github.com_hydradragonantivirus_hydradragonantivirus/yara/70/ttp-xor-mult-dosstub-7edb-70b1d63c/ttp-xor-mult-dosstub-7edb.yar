rule TTP_XOR_MULT_DOSStub_7edb {
  strings:
    $key_7edb = { 2a b3 [2] 5e ab [2] 19 a9 [2] 5e b8 [2] 10 b4 [2] 1c be [2] 0b b5 [2] 10 fb [2] 2d }

  condition:
    any of them
}
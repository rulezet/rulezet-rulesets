rule TTP_XOR_MULT_DOSStub_2edb {
  strings:
    $key_2edb = { 7a b3 [2] 0e ab [2] 49 a9 [2] 0e b8 [2] 40 b4 [2] 4c be [2] 5b b5 [2] 40 fb [2] 7d }

  condition:
    any of them
}
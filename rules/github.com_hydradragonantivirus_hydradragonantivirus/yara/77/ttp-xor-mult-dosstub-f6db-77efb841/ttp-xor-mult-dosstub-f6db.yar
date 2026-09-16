rule TTP_XOR_MULT_DOSStub_f6db {
  strings:
    $key_f6db = { a2 b3 [2] d6 ab [2] 91 a9 [2] d6 b8 [2] 98 b4 [2] 94 be [2] 83 b5 [2] 98 fb [2] a5 }

  condition:
    any of them
}
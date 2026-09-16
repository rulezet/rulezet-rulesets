rule TTP_XOR_MULT_DOSStub_02db {
  strings:
    $key_02db = { 56 b3 [2] 22 ab [2] 65 a9 [2] 22 b8 [2] 6c b4 [2] 60 be [2] 77 b5 [2] 6c fb [2] 51 }

  condition:
    any of them
}
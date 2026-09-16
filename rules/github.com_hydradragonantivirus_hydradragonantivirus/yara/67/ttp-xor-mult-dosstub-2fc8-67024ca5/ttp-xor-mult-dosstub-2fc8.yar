rule TTP_XOR_MULT_DOSStub_2fc8 {
  strings:
    $key_2fc8 = { 7b a0 [2] 0f b8 [2] 48 ba [2] 0f ab [2] 41 a7 [2] 4d ad [2] 5a a6 [2] 41 e8 [2] 7c }

  condition:
    any of them
}
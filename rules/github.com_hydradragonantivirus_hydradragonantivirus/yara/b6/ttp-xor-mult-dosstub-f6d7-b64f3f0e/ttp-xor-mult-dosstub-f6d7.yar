rule TTP_XOR_MULT_DOSStub_f6d7 {
  strings:
    $key_f6d7 = { a2 bf [2] d6 a7 [2] 91 a5 [2] d6 b4 [2] 98 b8 [2] 94 b2 [2] 83 b9 [2] 98 f7 [2] a5 }

  condition:
    any of them
}
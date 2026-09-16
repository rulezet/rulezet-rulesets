rule TTP_XOR_MULT_DOSStub_2fd1 {
  strings:
    $key_2fd1 = { 7b b9 [2] 0f a1 [2] 48 a3 [2] 0f b2 [2] 41 be [2] 4d b4 [2] 5a bf [2] 41 f1 [2] 7c }

  condition:
    any of them
}
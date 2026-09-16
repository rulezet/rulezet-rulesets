rule TTP_XOR_MULT_DOSStub_2ad0 {
  strings:
    $key_2ad0 = { 7e b8 [2] 0a a0 [2] 4d a2 [2] 0a b3 [2] 44 bf [2] 48 b5 [2] 5f be [2] 44 f0 [2] 79 }

  condition:
    any of them
}
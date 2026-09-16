rule TTP_XOR_MULT_DOSStub_6ad0 {
  strings:
    $key_6ad0 = { 3e b8 [2] 4a a0 [2] 0d a2 [2] 4a b3 [2] 04 bf [2] 08 b5 [2] 1f be [2] 04 f0 [2] 39 }

  condition:
    any of them
}
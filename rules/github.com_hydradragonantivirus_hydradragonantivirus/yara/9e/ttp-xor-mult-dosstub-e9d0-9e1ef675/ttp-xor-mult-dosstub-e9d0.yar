rule TTP_XOR_MULT_DOSStub_e9d0 {
  strings:
    $key_e9d0 = { bd b8 [2] c9 a0 [2] 8e a2 [2] c9 b3 [2] 87 bf [2] 8b b5 [2] 9c be [2] 87 f0 [2] ba }

  condition:
    any of them
}
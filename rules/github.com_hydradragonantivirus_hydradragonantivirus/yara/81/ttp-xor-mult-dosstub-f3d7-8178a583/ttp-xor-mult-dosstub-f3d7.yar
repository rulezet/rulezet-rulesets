rule TTP_XOR_MULT_DOSStub_f3d7 {
  strings:
    $key_f3d7 = { a7 bf [2] d3 a7 [2] 94 a5 [2] d3 b4 [2] 9d b8 [2] 91 b2 [2] 86 b9 [2] 9d f7 [2] a0 }

  condition:
    any of them
}
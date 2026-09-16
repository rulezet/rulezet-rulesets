rule TTP_XOR_MULT_DOSStub_f687 {
  strings:
    $key_f687 = { a2 ef [2] d6 f7 [2] 91 f5 [2] d6 e4 [2] 98 e8 [2] 94 e2 [2] 83 e9 [2] 98 a7 [2] a5 }

  condition:
    any of them
}
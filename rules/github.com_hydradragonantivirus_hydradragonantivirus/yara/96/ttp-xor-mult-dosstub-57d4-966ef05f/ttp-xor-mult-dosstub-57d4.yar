rule TTP_XOR_MULT_DOSStub_57d4 {
  strings:
    $key_57d4 = { 03 bc [2] 77 a4 [2] 30 a6 [2] 77 b7 [2] 39 bb [2] 35 b1 [2] 22 ba [2] 39 f4 [2] 04 }

  condition:
    any of them
}
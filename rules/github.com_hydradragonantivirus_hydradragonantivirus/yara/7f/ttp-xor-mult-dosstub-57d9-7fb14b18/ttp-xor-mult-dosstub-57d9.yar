rule TTP_XOR_MULT_DOSStub_57d9 {
  strings:
    $key_57d9 = { 03 b1 [2] 77 a9 [2] 30 ab [2] 77 ba [2] 39 b6 [2] 35 bc [2] 22 b7 [2] 39 f9 [2] 04 }

  condition:
    any of them
}
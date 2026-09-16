rule TTP_XOR_MULT_DOSStub_f471 {
  strings:
    $key_f471 = { a0 19 [2] d4 01 [2] 93 03 [2] d4 12 [2] 9a 1e [2] 96 14 [2] 81 1f [2] 9a 51 [2] a7 }

  condition:
    any of them
}
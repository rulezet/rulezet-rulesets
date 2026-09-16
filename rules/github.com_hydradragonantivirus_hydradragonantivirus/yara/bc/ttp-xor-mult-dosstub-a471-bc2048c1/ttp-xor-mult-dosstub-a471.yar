rule TTP_XOR_MULT_DOSStub_a471 {
  strings:
    $key_a471 = { f0 19 [2] 84 01 [2] c3 03 [2] 84 12 [2] ca 1e [2] c6 14 [2] d1 1f [2] ca 51 [2] f7 }

  condition:
    any of them
}
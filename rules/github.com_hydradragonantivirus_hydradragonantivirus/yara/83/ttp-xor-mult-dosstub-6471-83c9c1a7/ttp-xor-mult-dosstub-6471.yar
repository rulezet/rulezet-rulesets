rule TTP_XOR_MULT_DOSStub_6471 {
  strings:
    $key_6471 = { 30 19 [2] 44 01 [2] 03 03 [2] 44 12 [2] 0a 1e [2] 06 14 [2] 11 1f [2] 0a 51 [2] 37 }

  condition:
    any of them
}
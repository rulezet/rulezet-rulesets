rule TTP_XOR_MULT_DOSStub_3671 {
  strings:
    $key_3671 = { 62 19 [2] 16 01 [2] 51 03 [2] 16 12 [2] 58 1e [2] 54 14 [2] 43 1f [2] 58 51 [2] 65 }

  condition:
    any of them
}
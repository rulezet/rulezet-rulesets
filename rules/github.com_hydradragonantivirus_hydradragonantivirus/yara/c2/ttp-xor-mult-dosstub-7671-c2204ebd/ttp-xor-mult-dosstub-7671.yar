rule TTP_XOR_MULT_DOSStub_7671 {
  strings:
    $key_7671 = { 22 19 [2] 56 01 [2] 11 03 [2] 56 12 [2] 18 1e [2] 14 14 [2] 03 1f [2] 18 51 [2] 25 }

  condition:
    any of them
}
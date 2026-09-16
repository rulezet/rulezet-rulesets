rule TTP_XOR_MULT_DOSStub_7471 {
  strings:
    $key_7471 = { 20 19 [2] 54 01 [2] 13 03 [2] 54 12 [2] 1a 1e [2] 16 14 [2] 01 1f [2] 1a 51 [2] 27 }

  condition:
    any of them
}
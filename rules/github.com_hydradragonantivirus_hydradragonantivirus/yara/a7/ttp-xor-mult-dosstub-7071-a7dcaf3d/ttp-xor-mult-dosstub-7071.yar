rule TTP_XOR_MULT_DOSStub_7071 {
  strings:
    $key_7071 = { 24 19 [2] 50 01 [2] 17 03 [2] 50 12 [2] 1e 1e [2] 12 14 [2] 05 1f [2] 1e 51 [2] 23 }

  condition:
    any of them
}
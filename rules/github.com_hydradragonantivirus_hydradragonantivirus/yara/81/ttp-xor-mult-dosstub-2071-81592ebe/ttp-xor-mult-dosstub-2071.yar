rule TTP_XOR_MULT_DOSStub_2071 {
  strings:
    $key_2071 = { 74 19 [2] 00 01 [2] 47 03 [2] 00 12 [2] 4e 1e [2] 42 14 [2] 55 1f [2] 4e 51 [2] 73 }

  condition:
    any of them
}
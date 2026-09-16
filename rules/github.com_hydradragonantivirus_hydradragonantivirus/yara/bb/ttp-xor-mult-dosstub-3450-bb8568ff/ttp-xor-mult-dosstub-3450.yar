rule TTP_XOR_MULT_DOSStub_3450 {
  strings:
    $key_3450 = { 60 38 [2] 14 20 [2] 53 22 [2] 14 33 [2] 5a 3f [2] 56 35 [2] 41 3e [2] 5a 70 [2] 67 }

  condition:
    any of them
}
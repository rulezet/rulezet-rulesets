rule TTP_XOR_MULT_DOSStub_3211 {
  strings:
    $key_3211 = { 66 79 [2] 12 61 [2] 55 63 [2] 12 72 [2] 5c 7e [2] 50 74 [2] 47 7f [2] 5c 31 [2] 61 }

  condition:
    any of them
}
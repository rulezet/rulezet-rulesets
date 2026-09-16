rule TTP_XOR_MULT_DOSStub_3200 {
  strings:
    $key_3200 = { 66 68 [2] 12 70 [2] 55 72 [2] 12 63 [2] 5c 6f [2] 50 65 [2] 47 6e [2] 5c 20 [2] 61 }

  condition:
    any of them
}
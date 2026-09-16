rule TTP_XOR_MULT_DOSStub_0120 {
  strings:
    $key_0120 = { 55 48 [2] 21 50 [2] 66 52 [2] 21 43 [2] 6f 4f [2] 63 45 [2] 74 4e [2] 6f 00 [2] 52 }

  condition:
    any of them
}
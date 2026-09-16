rule TTP_XOR_MULT_DOSStub_3720 {
  strings:
    $key_3720 = { 63 48 [2] 17 50 [2] 50 52 [2] 17 43 [2] 59 4f [2] 55 45 [2] 42 4e [2] 59 00 [2] 64 }

  condition:
    any of them
}
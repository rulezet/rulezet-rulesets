rule TTP_XOR_MULT_DOSStub_3737 {
  strings:
    $key_3737 = { 63 5f [2] 17 47 [2] 50 45 [2] 17 54 [2] 59 58 [2] 55 52 [2] 42 59 [2] 59 17 [2] 64 }

  condition:
    any of them
}
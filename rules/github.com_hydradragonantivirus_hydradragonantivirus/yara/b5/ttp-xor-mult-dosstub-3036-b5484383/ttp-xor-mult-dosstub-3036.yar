rule TTP_XOR_MULT_DOSStub_3036 {
  strings:
    $key_3036 = { 64 5e [2] 10 46 [2] 57 44 [2] 10 55 [2] 5e 59 [2] 52 53 [2] 45 58 [2] 5e 16 [2] 63 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_3237 {
  strings:
    $key_3237 = { 66 5f [2] 12 47 [2] 55 45 [2] 12 54 [2] 5c 58 [2] 50 52 [2] 47 59 [2] 5c 17 [2] 61 }

  condition:
    any of them
}
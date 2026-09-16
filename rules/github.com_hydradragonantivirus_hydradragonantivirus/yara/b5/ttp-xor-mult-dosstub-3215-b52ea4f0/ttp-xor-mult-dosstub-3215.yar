rule TTP_XOR_MULT_DOSStub_3215 {
  strings:
    $key_3215 = { 66 7d [2] 12 65 [2] 55 67 [2] 12 76 [2] 5c 7a [2] 50 70 [2] 47 7b [2] 5c 35 [2] 61 }

  condition:
    any of them
}
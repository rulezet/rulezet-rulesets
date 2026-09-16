rule TTP_XOR_MULT_DOSStub_3515 {
  strings:
    $key_3515 = { 61 7d [2] 15 65 [2] 52 67 [2] 15 76 [2] 5b 7a [2] 57 70 [2] 40 7b [2] 5b 35 [2] 66 }

  condition:
    any of them
}
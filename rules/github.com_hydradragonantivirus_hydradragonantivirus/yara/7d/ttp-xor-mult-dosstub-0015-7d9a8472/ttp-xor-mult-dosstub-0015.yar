rule TTP_XOR_MULT_DOSStub_0015 {
  strings:
    $key_0015 = { 54 7d [2] 20 65 [2] 67 67 [2] 20 76 [2] 6e 7a [2] 62 70 [2] 75 7b [2] 6e 35 [2] 53 }

  condition:
    any of them
}
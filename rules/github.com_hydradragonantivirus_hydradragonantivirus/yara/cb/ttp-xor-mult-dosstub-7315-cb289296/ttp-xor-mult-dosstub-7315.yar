rule TTP_XOR_MULT_DOSStub_7315 {
  strings:
    $key_7315 = { 27 7d [2] 53 65 [2] 14 67 [2] 53 76 [2] 1d 7a [2] 11 70 [2] 06 7b [2] 1d 35 [2] 20 }

  condition:
    any of them
}
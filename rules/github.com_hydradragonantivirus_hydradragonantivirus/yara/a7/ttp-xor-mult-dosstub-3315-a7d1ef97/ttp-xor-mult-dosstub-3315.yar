rule TTP_XOR_MULT_DOSStub_3315 {
  strings:
    $key_3315 = { 67 7d [2] 13 65 [2] 54 67 [2] 13 76 [2] 5d 7a [2] 51 70 [2] 46 7b [2] 5d 35 [2] 60 }

  condition:
    any of them
}
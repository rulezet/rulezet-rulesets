rule TTP_XOR_MULT_DOSStub_3313 {
  strings:
    $key_3313 = { 67 7b [2] 13 63 [2] 54 61 [2] 13 70 [2] 5d 7c [2] 51 76 [2] 46 7d [2] 5d 33 [2] 60 }

  condition:
    any of them
}
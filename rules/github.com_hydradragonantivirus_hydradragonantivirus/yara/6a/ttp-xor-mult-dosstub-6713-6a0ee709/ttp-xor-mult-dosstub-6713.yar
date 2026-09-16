rule TTP_XOR_MULT_DOSStub_6713 {
  strings:
    $key_6713 = { 33 7b [2] 47 63 [2] 00 61 [2] 47 70 [2] 09 7c [2] 05 76 [2] 12 7d [2] 09 33 [2] 34 }

  condition:
    any of them
}
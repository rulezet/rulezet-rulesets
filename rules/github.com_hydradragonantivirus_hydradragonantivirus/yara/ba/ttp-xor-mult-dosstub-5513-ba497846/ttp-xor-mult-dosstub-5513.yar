rule TTP_XOR_MULT_DOSStub_5513 {
  strings:
    $key_5513 = { 01 7b [2] 75 63 [2] 32 61 [2] 75 70 [2] 3b 7c [2] 37 76 [2] 20 7d [2] 3b 33 [2] 06 }

  condition:
    any of them
}
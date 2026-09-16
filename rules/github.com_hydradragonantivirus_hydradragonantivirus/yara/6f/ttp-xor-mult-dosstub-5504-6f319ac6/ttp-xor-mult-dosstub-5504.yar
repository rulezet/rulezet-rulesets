rule TTP_XOR_MULT_DOSStub_5504 {
  strings:
    $key_5504 = { 01 6c [2] 75 74 [2] 32 76 [2] 75 67 [2] 3b 6b [2] 37 61 [2] 20 6a [2] 3b 24 [2] 06 }

  condition:
    any of them
}
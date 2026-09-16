rule TTP_XOR_MULT_DOSStub_6504 {
  strings:
    $key_6504 = { 31 6c [2] 45 74 [2] 02 76 [2] 45 67 [2] 0b 6b [2] 07 61 [2] 10 6a [2] 0b 24 [2] 36 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_3304 {
  strings:
    $key_3304 = { 67 6c [2] 13 74 [2] 54 76 [2] 13 67 [2] 5d 6b [2] 51 61 [2] 46 6a [2] 5d 24 [2] 60 }

  condition:
    any of them
}
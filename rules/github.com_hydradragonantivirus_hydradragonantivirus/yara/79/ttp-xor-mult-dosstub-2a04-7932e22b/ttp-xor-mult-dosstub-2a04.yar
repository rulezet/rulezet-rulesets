rule TTP_XOR_MULT_DOSStub_2a04 {
  strings:
    $key_2a04 = { 7e 6c [2] 0a 74 [2] 4d 76 [2] 0a 67 [2] 44 6b [2] 48 61 [2] 5f 6a [2] 44 24 [2] 79 }

  condition:
    any of them
}
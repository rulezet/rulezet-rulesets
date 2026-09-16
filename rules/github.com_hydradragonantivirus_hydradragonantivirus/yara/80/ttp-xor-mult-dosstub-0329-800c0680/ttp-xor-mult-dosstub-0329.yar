rule TTP_XOR_MULT_DOSStub_0329 {
  strings:
    $key_0329 = { 57 41 [2] 23 59 [2] 64 5b [2] 23 4a [2] 6d 46 [2] 61 4c [2] 76 47 [2] 6d 09 [2] 50 }

  condition:
    any of them
}
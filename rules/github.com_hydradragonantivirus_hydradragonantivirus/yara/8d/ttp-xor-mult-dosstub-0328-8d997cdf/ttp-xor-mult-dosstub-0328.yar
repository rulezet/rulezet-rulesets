rule TTP_XOR_MULT_DOSStub_0328 {
  strings:
    $key_0328 = { 57 40 [2] 23 58 [2] 64 5a [2] 23 4b [2] 6d 47 [2] 61 4d [2] 76 46 [2] 6d 08 [2] 50 }

  condition:
    any of them
}
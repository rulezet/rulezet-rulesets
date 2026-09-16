rule TTP_XOR_MULT_DOSStub_13e5 {
  strings:
    $key_13e5 = { 47 8d [2] 33 95 [2] 74 97 [2] 33 86 [2] 7d 8a [2] 71 80 [2] 66 8b [2] 7d c5 [2] 40 }

  condition:
    any of them
}
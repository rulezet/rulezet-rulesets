rule TTP_XOR_MULT_DOSStub_13e3 {
  strings:
    $key_13e3 = { 47 8b [2] 33 93 [2] 74 91 [2] 33 80 [2] 7d 8c [2] 71 86 [2] 66 8d [2] 7d c3 [2] 40 }

  condition:
    any of them
}
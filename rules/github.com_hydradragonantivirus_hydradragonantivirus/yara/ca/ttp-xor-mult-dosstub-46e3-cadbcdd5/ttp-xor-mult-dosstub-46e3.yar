rule TTP_XOR_MULT_DOSStub_46e3 {
  strings:
    $key_46e3 = { 12 8b [2] 66 93 [2] 21 91 [2] 66 80 [2] 28 8c [2] 24 86 [2] 33 8d [2] 28 c3 [2] 15 }

  condition:
    any of them
}
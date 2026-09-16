rule TTP_XOR_MULT_DOSStub_67e3 {
  strings:
    $key_67e3 = { 33 8b [2] 47 93 [2] 00 91 [2] 47 80 [2] 09 8c [2] 05 86 [2] 12 8d [2] 09 c3 [2] 34 }

  condition:
    any of them
}
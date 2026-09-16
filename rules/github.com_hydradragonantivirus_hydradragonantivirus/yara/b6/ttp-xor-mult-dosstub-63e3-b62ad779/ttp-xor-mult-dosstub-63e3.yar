rule TTP_XOR_MULT_DOSStub_63e3 {
  strings:
    $key_63e3 = { 37 8b [2] 43 93 [2] 04 91 [2] 43 80 [2] 0d 8c [2] 01 86 [2] 16 8d [2] 0d c3 [2] 30 }

  condition:
    any of them
}
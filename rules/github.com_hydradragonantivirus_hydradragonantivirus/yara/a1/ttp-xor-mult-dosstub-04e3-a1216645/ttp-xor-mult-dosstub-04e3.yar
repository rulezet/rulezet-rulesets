rule TTP_XOR_MULT_DOSStub_04e3 {
  strings:
    $key_04e3 = { 50 8b [2] 24 93 [2] 63 91 [2] 24 80 [2] 6a 8c [2] 66 86 [2] 71 8d [2] 6a c3 [2] 57 }

  condition:
    any of them
}
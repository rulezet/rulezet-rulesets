rule TTP_XOR_MULT_DOSStub_37e3 {
  strings:
    $key_37e3 = { 63 8b [2] 17 93 [2] 50 91 [2] 17 80 [2] 59 8c [2] 55 86 [2] 42 8d [2] 59 c3 [2] 64 }

  condition:
    any of them
}
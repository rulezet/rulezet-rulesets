rule TTP_XOR_MULT_DOSStub_76e3 {
  strings:
    $key_76e3 = { 22 8b [2] 56 93 [2] 11 91 [2] 56 80 [2] 18 8c [2] 14 86 [2] 03 8d [2] 18 c3 [2] 25 }

  condition:
    any of them
}
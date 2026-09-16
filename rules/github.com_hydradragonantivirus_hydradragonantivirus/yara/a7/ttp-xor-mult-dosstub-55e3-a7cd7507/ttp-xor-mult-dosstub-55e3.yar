rule TTP_XOR_MULT_DOSStub_55e3 {
  strings:
    $key_55e3 = { 01 8b [2] 75 93 [2] 32 91 [2] 75 80 [2] 3b 8c [2] 37 86 [2] 20 8d [2] 3b c3 [2] 06 }

  condition:
    any of them
}
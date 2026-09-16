rule TTP_XOR_MULT_DOSStub_50e3 {
  strings:
    $key_50e3 = { 04 8b [2] 70 93 [2] 37 91 [2] 70 80 [2] 3e 8c [2] 32 86 [2] 25 8d [2] 3e c3 [2] 03 }

  condition:
    any of them
}
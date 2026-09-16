rule TTP_XOR_MULT_DOSStub_70e3 {
  strings:
    $key_70e3 = { 24 8b [2] 50 93 [2] 17 91 [2] 50 80 [2] 1e 8c [2] 12 86 [2] 05 8d [2] 1e c3 [2] 23 }

  condition:
    any of them
}
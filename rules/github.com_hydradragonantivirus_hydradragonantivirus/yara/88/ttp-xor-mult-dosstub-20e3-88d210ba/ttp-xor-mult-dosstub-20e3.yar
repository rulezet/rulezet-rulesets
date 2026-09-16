rule TTP_XOR_MULT_DOSStub_20e3 {
  strings:
    $key_20e3 = { 74 8b [2] 00 93 [2] 47 91 [2] 00 80 [2] 4e 8c [2] 42 86 [2] 55 8d [2] 4e c3 [2] 73 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_62e3 {
  strings:
    $key_62e3 = { 36 8b [2] 42 93 [2] 05 91 [2] 42 80 [2] 0c 8c [2] 00 86 [2] 17 8d [2] 0c c3 [2] 31 }

  condition:
    any of them
}
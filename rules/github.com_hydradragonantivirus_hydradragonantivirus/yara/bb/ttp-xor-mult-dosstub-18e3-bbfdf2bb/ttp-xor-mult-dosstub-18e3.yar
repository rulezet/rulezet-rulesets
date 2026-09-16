rule TTP_XOR_MULT_DOSStub_18e3 {
  strings:
    $key_18e3 = { 4c 8b [2] 38 93 [2] 7f 91 [2] 38 80 [2] 76 8c [2] 7a 86 [2] 6d 8d [2] 76 c3 [2] 4b }

  condition:
    any of them
}
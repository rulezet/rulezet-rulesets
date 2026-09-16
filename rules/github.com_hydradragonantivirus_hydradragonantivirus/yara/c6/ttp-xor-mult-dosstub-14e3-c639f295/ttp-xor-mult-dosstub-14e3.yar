rule TTP_XOR_MULT_DOSStub_14e3 {
  strings:
    $key_14e3 = { 40 8b [2] 34 93 [2] 73 91 [2] 34 80 [2] 7a 8c [2] 76 86 [2] 61 8d [2] 7a c3 [2] 47 }

  condition:
    any of them
}
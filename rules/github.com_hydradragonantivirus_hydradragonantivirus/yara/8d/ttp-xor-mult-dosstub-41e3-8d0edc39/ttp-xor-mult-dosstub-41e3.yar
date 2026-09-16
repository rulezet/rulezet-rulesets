rule TTP_XOR_MULT_DOSStub_41e3 {
  strings:
    $key_41e3 = { 15 8b [2] 61 93 [2] 26 91 [2] 61 80 [2] 2f 8c [2] 23 86 [2] 34 8d [2] 2f c3 [2] 12 }

  condition:
    any of them
}
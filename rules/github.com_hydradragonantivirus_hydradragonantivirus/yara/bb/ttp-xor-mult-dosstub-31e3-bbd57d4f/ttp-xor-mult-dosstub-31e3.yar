rule TTP_XOR_MULT_DOSStub_31e3 {
  strings:
    $key_31e3 = { 65 8b [2] 11 93 [2] 56 91 [2] 11 80 [2] 5f 8c [2] 53 86 [2] 44 8d [2] 5f c3 [2] 62 }

  condition:
    any of them
}
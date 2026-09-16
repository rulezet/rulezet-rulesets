rule TTP_XOR_MULT_DOSStub_35e3 {
  strings:
    $key_35e3 = { 61 8b [2] 15 93 [2] 52 91 [2] 15 80 [2] 5b 8c [2] 57 86 [2] 40 8d [2] 5b c3 [2] 66 }

  condition:
    any of them
}
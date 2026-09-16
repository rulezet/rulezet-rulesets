rule TTP_XOR_MULT_DOSStub_77e5 {
  strings:
    $key_77e5 = { 23 8d [2] 57 95 [2] 10 97 [2] 57 86 [2] 19 8a [2] 15 80 [2] 02 8b [2] 19 c5 [2] 24 }

  condition:
    any of them
}
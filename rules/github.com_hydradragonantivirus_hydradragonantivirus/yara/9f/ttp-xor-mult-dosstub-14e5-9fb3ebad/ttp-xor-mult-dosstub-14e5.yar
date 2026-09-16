rule TTP_XOR_MULT_DOSStub_14e5 {
  strings:
    $key_14e5 = { 40 8d [2] 34 95 [2] 73 97 [2] 34 86 [2] 7a 8a [2] 76 80 [2] 61 8b [2] 7a c5 [2] 47 }

  condition:
    any of them
}
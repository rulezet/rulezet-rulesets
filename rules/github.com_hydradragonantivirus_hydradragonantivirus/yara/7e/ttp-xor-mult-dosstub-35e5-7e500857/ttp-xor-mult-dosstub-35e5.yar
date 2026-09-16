rule TTP_XOR_MULT_DOSStub_35e5 {
  strings:
    $key_35e5 = { 61 8d [2] 15 95 [2] 52 97 [2] 15 86 [2] 5b 8a [2] 57 80 [2] 40 8b [2] 5b c5 [2] 66 }

  condition:
    any of them
}
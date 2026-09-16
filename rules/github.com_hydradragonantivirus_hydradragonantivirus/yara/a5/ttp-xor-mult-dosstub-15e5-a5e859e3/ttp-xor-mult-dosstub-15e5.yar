rule TTP_XOR_MULT_DOSStub_15e5 {
  strings:
    $key_15e5 = { 41 8d [2] 35 95 [2] 72 97 [2] 35 86 [2] 7b 8a [2] 77 80 [2] 60 8b [2] 7b c5 [2] 46 }

  condition:
    any of them
}
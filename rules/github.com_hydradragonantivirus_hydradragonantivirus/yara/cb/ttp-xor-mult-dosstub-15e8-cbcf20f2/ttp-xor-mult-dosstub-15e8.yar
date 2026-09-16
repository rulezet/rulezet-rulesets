rule TTP_XOR_MULT_DOSStub_15e8 {
  strings:
    $key_15e8 = { 41 80 [2] 35 98 [2] 72 9a [2] 35 8b [2] 7b 87 [2] 77 8d [2] 60 86 [2] 7b c8 [2] 46 }

  condition:
    any of them
}
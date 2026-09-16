rule TTP_XOR_MULT_DOSStub_1578 {
  strings:
    $key_1578 = { 41 10 [2] 35 08 [2] 72 0a [2] 35 1b [2] 7b 17 [2] 77 1d [2] 60 16 [2] 7b 58 [2] 46 }

  condition:
    any of them
}
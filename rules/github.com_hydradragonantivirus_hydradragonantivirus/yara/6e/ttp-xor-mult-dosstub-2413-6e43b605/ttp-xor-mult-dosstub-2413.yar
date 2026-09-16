rule TTP_XOR_MULT_DOSStub_2413 {
  strings:
    $key_2413 = { 70 7b [2] 04 63 [2] 43 61 [2] 04 70 [2] 4a 7c [2] 46 76 [2] 51 7d [2] 4a 33 [2] 77 }

  condition:
    any of them
}
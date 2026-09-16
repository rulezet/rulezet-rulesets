rule TTP_XOR_MULT_DOSStub_2422 {
  strings:
    $key_2422 = { 70 4a [2] 04 52 [2] 43 50 [2] 04 41 [2] 4a 4d [2] 46 47 [2] 51 4c [2] 4a 02 [2] 77 }

  condition:
    any of them
}
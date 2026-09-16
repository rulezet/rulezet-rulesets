rule TTP_XOR_MULT_DOSStub_2435 {
  strings:
    $key_2435 = { 70 5d [2] 04 45 [2] 43 47 [2] 04 56 [2] 4a 5a [2] 46 50 [2] 51 5b [2] 4a 15 [2] 77 }

  condition:
    any of them
}
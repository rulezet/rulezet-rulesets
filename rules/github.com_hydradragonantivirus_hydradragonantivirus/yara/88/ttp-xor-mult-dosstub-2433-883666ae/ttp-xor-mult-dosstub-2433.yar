rule TTP_XOR_MULT_DOSStub_2433 {
  strings:
    $key_2433 = { 70 5b [2] 04 43 [2] 43 41 [2] 04 50 [2] 4a 5c [2] 46 56 [2] 51 5d [2] 4a 13 [2] 77 }

  condition:
    any of them
}
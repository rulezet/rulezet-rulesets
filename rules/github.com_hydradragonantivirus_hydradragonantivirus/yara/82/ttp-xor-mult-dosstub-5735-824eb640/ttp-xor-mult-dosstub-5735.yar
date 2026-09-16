rule TTP_XOR_MULT_DOSStub_5735 {
  strings:
    $key_5735 = { 03 5d [2] 77 45 [2] 30 47 [2] 77 56 [2] 39 5a [2] 35 50 [2] 22 5b [2] 39 15 [2] 04 }

  condition:
    any of them
}
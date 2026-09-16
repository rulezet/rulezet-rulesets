rule TTP_XOR_MULT_DOSStub_2405 {
  strings:
    $key_2405 = { 70 6d [2] 04 75 [2] 43 77 [2] 04 66 [2] 4a 6a [2] 46 60 [2] 51 6b [2] 4a 25 [2] 77 }

  condition:
    any of them
}
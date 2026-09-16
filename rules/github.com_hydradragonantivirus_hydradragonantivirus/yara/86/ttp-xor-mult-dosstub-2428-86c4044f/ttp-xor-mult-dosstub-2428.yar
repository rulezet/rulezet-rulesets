rule TTP_XOR_MULT_DOSStub_2428 {
  strings:
    $key_2428 = { 70 40 [2] 04 58 [2] 43 5a [2] 04 4b [2] 4a 47 [2] 46 4d [2] 51 46 [2] 4a 08 [2] 77 }

  condition:
    any of them
}
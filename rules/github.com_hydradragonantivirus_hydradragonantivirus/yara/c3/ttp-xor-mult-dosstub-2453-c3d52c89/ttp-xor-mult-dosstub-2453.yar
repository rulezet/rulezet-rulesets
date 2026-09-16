rule TTP_XOR_MULT_DOSStub_2453 {
  strings:
    $key_2453 = { 70 3b [2] 04 23 [2] 43 21 [2] 04 30 [2] 4a 3c [2] 46 36 [2] 51 3d [2] 4a 73 [2] 77 }

  condition:
    any of them
}
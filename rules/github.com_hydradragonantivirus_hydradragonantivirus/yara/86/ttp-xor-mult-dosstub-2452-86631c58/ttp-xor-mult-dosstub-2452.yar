rule TTP_XOR_MULT_DOSStub_2452 {
  strings:
    $key_2452 = { 70 3a [2] 04 22 [2] 43 20 [2] 04 31 [2] 4a 3d [2] 46 37 [2] 51 3c [2] 4a 72 [2] 77 }

  condition:
    any of them
}
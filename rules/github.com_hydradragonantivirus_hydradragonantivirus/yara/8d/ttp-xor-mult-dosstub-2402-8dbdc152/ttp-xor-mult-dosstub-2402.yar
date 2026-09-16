rule TTP_XOR_MULT_DOSStub_2402 {
  strings:
    $key_2402 = { 70 6a [2] 04 72 [2] 43 70 [2] 04 61 [2] 4a 6d [2] 46 67 [2] 51 6c [2] 4a 22 [2] 77 }

  condition:
    any of them
}
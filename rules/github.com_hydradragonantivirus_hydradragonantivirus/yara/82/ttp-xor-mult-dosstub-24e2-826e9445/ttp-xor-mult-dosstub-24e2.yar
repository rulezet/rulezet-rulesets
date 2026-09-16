rule TTP_XOR_MULT_DOSStub_24e2 {
  strings:
    $key_24e2 = { 70 8a [2] 04 92 [2] 43 90 [2] 04 81 [2] 4a 8d [2] 46 87 [2] 51 8c [2] 4a c2 [2] 77 }

  condition:
    any of them
}
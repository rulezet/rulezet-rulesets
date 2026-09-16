rule TTP_XOR_MULT_DOSStub_24d0 {
  strings:
    $key_24d0 = { 70 b8 [2] 04 a0 [2] 43 a2 [2] 04 b3 [2] 4a bf [2] 46 b5 [2] 51 be [2] 4a f0 [2] 77 }

  condition:
    any of them
}
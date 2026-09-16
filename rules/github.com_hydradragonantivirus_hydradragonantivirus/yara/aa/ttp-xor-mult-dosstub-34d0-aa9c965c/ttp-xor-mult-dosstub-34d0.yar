rule TTP_XOR_MULT_DOSStub_34d0 {
  strings:
    $key_34d0 = { 60 b8 [2] 14 a0 [2] 53 a2 [2] 14 b3 [2] 5a bf [2] 56 b5 [2] 41 be [2] 5a f0 [2] 67 }

  condition:
    any of them
}
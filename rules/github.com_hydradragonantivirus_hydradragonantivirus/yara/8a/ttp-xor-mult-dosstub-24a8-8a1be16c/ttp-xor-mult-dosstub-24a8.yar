rule TTP_XOR_MULT_DOSStub_24a8 {
  strings:
    $key_24a8 = { 70 c0 [2] 04 d8 [2] 43 da [2] 04 cb [2] 4a c7 [2] 46 cd [2] 51 c6 [2] 4a 88 [2] 77 }

  condition:
    any of them
}
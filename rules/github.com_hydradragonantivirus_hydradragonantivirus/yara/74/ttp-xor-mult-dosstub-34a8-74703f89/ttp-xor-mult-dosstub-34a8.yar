rule TTP_XOR_MULT_DOSStub_34a8 {
  strings:
    $key_34a8 = { 60 c0 [2] 14 d8 [2] 53 da [2] 14 cb [2] 5a c7 [2] 56 cd [2] 41 c6 [2] 5a 88 [2] 67 }

  condition:
    any of them
}
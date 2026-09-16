rule TTP_XOR_MULT_DOSStub_f4a8 {
  strings:
    $key_f4a8 = { a0 c0 [2] d4 d8 [2] 93 da [2] d4 cb [2] 9a c7 [2] 96 cd [2] 81 c6 [2] 9a 88 [2] a7 }

  condition:
    any of them
}
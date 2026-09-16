rule TTP_XOR_MULT_DOSStub_f5a8 {
  strings:
    $key_f5a8 = { a1 c0 [2] d5 d8 [2] 92 da [2] d5 cb [2] 9b c7 [2] 97 cd [2] 80 c6 [2] 9b 88 [2] a6 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_f2a5 {
  strings:
    $key_f2a5 = { a6 cd [2] d2 d5 [2] 95 d7 [2] d2 c6 [2] 9c ca [2] 90 c0 [2] 87 cb [2] 9c 85 [2] a1 }

  condition:
    any of them
}
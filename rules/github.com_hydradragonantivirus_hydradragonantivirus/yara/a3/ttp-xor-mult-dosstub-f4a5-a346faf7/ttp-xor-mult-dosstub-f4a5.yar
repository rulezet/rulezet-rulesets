rule TTP_XOR_MULT_DOSStub_f4a5 {
  strings:
    $key_f4a5 = { a0 cd [2] d4 d5 [2] 93 d7 [2] d4 c6 [2] 9a ca [2] 96 c0 [2] 81 cb [2] 9a 85 [2] a7 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_f7a5 {
  strings:
    $key_f7a5 = { a3 cd [2] d7 d5 [2] 90 d7 [2] d7 c6 [2] 99 ca [2] 95 c0 [2] 82 cb [2] 99 85 [2] a4 }

  condition:
    any of them
}
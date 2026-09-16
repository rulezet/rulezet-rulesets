rule TTP_XOR_MULT_DOSStub_f6a5 {
  strings:
    $key_f6a5 = { a2 cd [2] d6 d5 [2] 91 d7 [2] d6 c6 [2] 98 ca [2] 94 c0 [2] 83 cb [2] 98 85 [2] a5 }

  condition:
    any of them
}
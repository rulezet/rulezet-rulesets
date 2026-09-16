rule TTP_XOR_MULT_DOSStub_f0a4 {
  strings:
    $key_f0a4 = { a4 cc [2] d0 d4 [2] 97 d6 [2] d0 c7 [2] 9e cb [2] 92 c1 [2] 85 ca [2] 9e 84 [2] a3 }

  condition:
    any of them
}
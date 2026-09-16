rule TTP_XOR_MULT_DOSStub_f0a2 {
  strings:
    $key_f0a2 = { a4 ca [2] d0 d2 [2] 97 d0 [2] d0 c1 [2] 9e cd [2] 92 c7 [2] 85 cc [2] 9e 82 [2] a3 }

  condition:
    any of them
}
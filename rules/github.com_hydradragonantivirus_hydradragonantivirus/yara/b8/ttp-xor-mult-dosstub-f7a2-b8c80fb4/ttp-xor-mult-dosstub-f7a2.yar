rule TTP_XOR_MULT_DOSStub_f7a2 {
  strings:
    $key_f7a2 = { a3 ca [2] d7 d2 [2] 90 d0 [2] d7 c1 [2] 99 cd [2] 95 c7 [2] 82 cc [2] 99 82 [2] a4 }

  condition:
    any of them
}
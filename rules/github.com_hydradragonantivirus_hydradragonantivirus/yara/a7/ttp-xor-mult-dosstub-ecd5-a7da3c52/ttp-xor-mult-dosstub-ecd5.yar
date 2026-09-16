rule TTP_XOR_MULT_DOSStub_ecd5 {
  strings:
    $key_ecd5 = { b8 bd [2] cc a5 [2] 8b a7 [2] cc b6 [2] 82 ba [2] 8e b0 [2] 99 bb [2] 82 f5 [2] bf }

  condition:
    any of them
}
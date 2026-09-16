rule TTP_XOR_MULT_DOSStub_ecd3 {
  strings:
    $key_ecd3 = { b8 bb [2] cc a3 [2] 8b a1 [2] cc b0 [2] 82 bc [2] 8e b6 [2] 99 bd [2] 82 f3 [2] bf }

  condition:
    any of them
}
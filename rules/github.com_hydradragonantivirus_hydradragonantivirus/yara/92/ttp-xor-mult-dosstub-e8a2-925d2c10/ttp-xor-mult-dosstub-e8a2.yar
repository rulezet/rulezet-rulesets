rule TTP_XOR_MULT_DOSStub_e8a2 {
  strings:
    $key_e8a2 = { bc ca [2] c8 d2 [2] 8f d0 [2] c8 c1 [2] 86 cd [2] 8a c7 [2] 9d cc [2] 86 82 [2] bb }

  condition:
    any of them
}
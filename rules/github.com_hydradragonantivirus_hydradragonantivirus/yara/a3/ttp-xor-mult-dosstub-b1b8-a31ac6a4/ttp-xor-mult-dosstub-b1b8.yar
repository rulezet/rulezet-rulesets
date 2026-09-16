rule TTP_XOR_MULT_DOSStub_b1b8 {
  strings:
    $key_b1b8 = { e5 d0 [2] 91 c8 [2] d6 ca [2] 91 db [2] df d7 [2] d3 dd [2] c4 d6 [2] df 98 [2] e2 }

  condition:
    any of them
}
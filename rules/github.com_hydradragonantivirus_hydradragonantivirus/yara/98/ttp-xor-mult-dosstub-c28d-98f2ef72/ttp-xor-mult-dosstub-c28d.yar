rule TTP_XOR_MULT_DOSStub_c28d {
  strings:
    $key_c28d = { 96 e5 [2] e2 fd [2] a5 ff [2] e2 ee [2] ac e2 [2] a0 e8 [2] b7 e3 [2] ac ad [2] 91 }

  condition:
    any of them
}
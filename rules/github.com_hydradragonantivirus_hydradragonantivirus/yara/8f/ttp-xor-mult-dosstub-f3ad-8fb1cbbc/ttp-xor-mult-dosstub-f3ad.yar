rule TTP_XOR_MULT_DOSStub_f3ad {
  strings:
    $key_f3ad = { a7 c5 [2] d3 dd [2] 94 df [2] d3 ce [2] 9d c2 [2] 91 c8 [2] 86 c3 [2] 9d 8d [2] a0 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_f1af {
  strings:
    $key_f1af = { a5 c7 [2] d1 df [2] 96 dd [2] d1 cc [2] 9f c0 [2] 93 ca [2] 84 c1 [2] 9f 8f [2] a2 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_f4af {
  strings:
    $key_f4af = { a0 c7 [2] d4 df [2] 93 dd [2] d4 cc [2] 9a c0 [2] 96 ca [2] 81 c1 [2] 9a 8f [2] a7 }

  condition:
    any of them
}
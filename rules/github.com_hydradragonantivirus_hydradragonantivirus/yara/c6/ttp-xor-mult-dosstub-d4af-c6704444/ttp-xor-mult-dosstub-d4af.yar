rule TTP_XOR_MULT_DOSStub_d4af {
  strings:
    $key_d4af = { 80 c7 [2] f4 df [2] b3 dd [2] f4 cc [2] ba c0 [2] b6 ca [2] a1 c1 [2] ba 8f [2] 87 }

  condition:
    any of them
}
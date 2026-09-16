rule TTP_XOR_MULT_DOSStub_54af {
  strings:
    $key_54af = { 00 c7 [2] 74 df [2] 33 dd [2] 74 cc [2] 3a c0 [2] 36 ca [2] 21 c1 [2] 3a 8f [2] 07 }

  condition:
    any of them
}
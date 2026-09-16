rule TTP_XOR_MULT_DOSStub_45af {
  strings:
    $key_45af = { 11 c7 [2] 65 df [2] 22 dd [2] 65 cc [2] 2b c0 [2] 27 ca [2] 30 c1 [2] 2b 8f [2] 16 }

  condition:
    any of them
}
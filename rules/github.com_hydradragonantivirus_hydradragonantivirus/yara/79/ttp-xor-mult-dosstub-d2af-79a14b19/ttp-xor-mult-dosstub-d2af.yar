rule TTP_XOR_MULT_DOSStub_d2af {
  strings:
    $key_d2af = { 86 c7 [2] f2 df [2] b5 dd [2] f2 cc [2] bc c0 [2] b0 ca [2] a7 c1 [2] bc 8f [2] 81 }

  condition:
    any of them
}
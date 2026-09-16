rule TTP_XOR_MULT_DOSStub_c6af {
  strings:
    $key_c6af = { 92 c7 [2] e6 df [2] a1 dd [2] e6 cc [2] a8 c0 [2] a4 ca [2] b3 c1 [2] a8 8f [2] 95 }

  condition:
    any of them
}
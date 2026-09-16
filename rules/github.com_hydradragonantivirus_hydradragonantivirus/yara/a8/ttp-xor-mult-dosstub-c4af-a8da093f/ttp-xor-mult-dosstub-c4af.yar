rule TTP_XOR_MULT_DOSStub_c4af {
  strings:
    $key_c4af = { 90 c7 [2] e4 df [2] a3 dd [2] e4 cc [2] aa c0 [2] a6 ca [2] b1 c1 [2] aa 8f [2] 97 }

  condition:
    any of them
}
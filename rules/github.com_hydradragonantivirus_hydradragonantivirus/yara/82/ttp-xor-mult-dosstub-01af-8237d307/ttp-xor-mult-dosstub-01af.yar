rule TTP_XOR_MULT_DOSStub_01af {
  strings:
    $key_01af = { 55 c7 [2] 21 df [2] 66 dd [2] 21 cc [2] 6f c0 [2] 63 ca [2] 74 c1 [2] 6f 8f [2] 52 }

  condition:
    any of them
}
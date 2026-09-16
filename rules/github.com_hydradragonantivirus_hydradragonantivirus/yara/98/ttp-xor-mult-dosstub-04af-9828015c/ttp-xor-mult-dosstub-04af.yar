rule TTP_XOR_MULT_DOSStub_04af {
  strings:
    $key_04af = { 50 c7 [2] 24 df [2] 63 dd [2] 24 cc [2] 6a c0 [2] 66 ca [2] 71 c1 [2] 6a 8f [2] 57 }

  condition:
    any of them
}
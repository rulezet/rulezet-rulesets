rule TTP_XOR_MULT_DOSStub_41af {
  strings:
    $key_41af = { 15 c7 [2] 61 df [2] 26 dd [2] 61 cc [2] 2f c0 [2] 23 ca [2] 34 c1 [2] 2f 8f [2] 12 }

  condition:
    any of them
}
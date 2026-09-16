rule TTP_XOR_MULT_DOSStub_31af {
  strings:
    $key_31af = { 65 c7 [2] 11 df [2] 56 dd [2] 11 cc [2] 5f c0 [2] 53 ca [2] 44 c1 [2] 5f 8f [2] 62 }

  condition:
    any of them
}
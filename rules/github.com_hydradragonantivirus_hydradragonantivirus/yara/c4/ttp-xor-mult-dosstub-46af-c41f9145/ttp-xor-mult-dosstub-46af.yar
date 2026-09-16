rule TTP_XOR_MULT_DOSStub_46af {
  strings:
    $key_46af = { 12 c7 [2] 66 df [2] 21 dd [2] 66 cc [2] 28 c0 [2] 24 ca [2] 33 c1 [2] 28 8f [2] 15 }

  condition:
    any of them
}
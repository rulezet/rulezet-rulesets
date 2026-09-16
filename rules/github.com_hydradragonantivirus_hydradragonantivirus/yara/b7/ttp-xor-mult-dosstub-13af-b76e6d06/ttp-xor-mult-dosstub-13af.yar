rule TTP_XOR_MULT_DOSStub_13af {
  strings:
    $key_13af = { 47 c7 [2] 33 df [2] 74 dd [2] 33 cc [2] 7d c0 [2] 71 ca [2] 66 c1 [2] 7d 8f [2] 40 }

  condition:
    any of them
}
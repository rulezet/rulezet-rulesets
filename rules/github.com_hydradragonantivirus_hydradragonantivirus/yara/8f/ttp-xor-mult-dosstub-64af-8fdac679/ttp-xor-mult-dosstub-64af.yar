rule TTP_XOR_MULT_DOSStub_64af {
  strings:
    $key_64af = { 30 c7 [2] 44 df [2] 03 dd [2] 44 cc [2] 0a c0 [2] 06 ca [2] 11 c1 [2] 0a 8f [2] 37 }

  condition:
    any of them
}
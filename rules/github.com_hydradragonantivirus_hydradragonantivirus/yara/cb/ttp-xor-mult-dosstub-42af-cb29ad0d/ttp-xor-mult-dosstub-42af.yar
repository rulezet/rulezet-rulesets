rule TTP_XOR_MULT_DOSStub_42af {
  strings:
    $key_42af = { 16 c7 [2] 62 df [2] 25 dd [2] 62 cc [2] 2c c0 [2] 20 ca [2] 37 c1 [2] 2c 8f [2] 11 }

  condition:
    any of them
}
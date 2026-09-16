rule TTP_XOR_MULT_DOSStub_77af {
  strings:
    $key_77af = { 23 c7 [2] 57 df [2] 10 dd [2] 57 cc [2] 19 c0 [2] 15 ca [2] 02 c1 [2] 19 8f [2] 24 }

  condition:
    any of them
}
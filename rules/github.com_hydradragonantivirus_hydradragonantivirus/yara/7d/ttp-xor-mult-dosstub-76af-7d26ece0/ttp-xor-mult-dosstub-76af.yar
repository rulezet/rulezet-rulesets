rule TTP_XOR_MULT_DOSStub_76af {
  strings:
    $key_76af = { 22 c7 [2] 56 df [2] 11 dd [2] 56 cc [2] 18 c0 [2] 14 ca [2] 03 c1 [2] 18 8f [2] 25 }

  condition:
    any of them
}
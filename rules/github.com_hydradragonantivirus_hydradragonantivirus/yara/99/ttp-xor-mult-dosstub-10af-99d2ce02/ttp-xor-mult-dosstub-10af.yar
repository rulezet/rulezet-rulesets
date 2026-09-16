rule TTP_XOR_MULT_DOSStub_10af {
  strings:
    $key_10af = { 44 c7 [2] 30 df [2] 77 dd [2] 30 cc [2] 7e c0 [2] 72 ca [2] 65 c1 [2] 7e 8f [2] 43 }

  condition:
    any of them
}
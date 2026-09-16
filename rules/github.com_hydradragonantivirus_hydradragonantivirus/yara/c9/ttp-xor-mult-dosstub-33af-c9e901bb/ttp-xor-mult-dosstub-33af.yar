rule TTP_XOR_MULT_DOSStub_33af {
  strings:
    $key_33af = { 67 c7 [2] 13 df [2] 54 dd [2] 13 cc [2] 5d c0 [2] 51 ca [2] 46 c1 [2] 5d 8f [2] 60 }

  condition:
    any of them
}
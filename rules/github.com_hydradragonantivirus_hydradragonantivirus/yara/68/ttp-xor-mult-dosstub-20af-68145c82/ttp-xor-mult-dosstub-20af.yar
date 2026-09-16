rule TTP_XOR_MULT_DOSStub_20af {
  strings:
    $key_20af = { 74 c7 [2] 00 df [2] 47 dd [2] 00 cc [2] 4e c0 [2] 42 ca [2] 55 c1 [2] 4e 8f [2] 73 }

  condition:
    any of them
}
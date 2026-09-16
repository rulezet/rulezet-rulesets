rule TTP_XOR_MULT_DOSStub_37af {
  strings:
    $key_37af = { 63 c7 [2] 17 df [2] 50 dd [2] 17 cc [2] 59 c0 [2] 55 ca [2] 42 c1 [2] 59 8f [2] 64 }

  condition:
    any of them
}
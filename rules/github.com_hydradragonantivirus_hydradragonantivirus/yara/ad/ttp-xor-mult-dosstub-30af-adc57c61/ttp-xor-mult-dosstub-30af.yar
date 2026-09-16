rule TTP_XOR_MULT_DOSStub_30af {
  strings:
    $key_30af = { 64 c7 [2] 10 df [2] 57 dd [2] 10 cc [2] 5e c0 [2] 52 ca [2] 45 c1 [2] 5e 8f [2] 63 }

  condition:
    any of them
}
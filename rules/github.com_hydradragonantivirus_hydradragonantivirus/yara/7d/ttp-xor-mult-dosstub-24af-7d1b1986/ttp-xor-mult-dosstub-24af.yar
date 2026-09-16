rule TTP_XOR_MULT_DOSStub_24af {
  strings:
    $key_24af = { 70 c7 [2] 04 df [2] 43 dd [2] 04 cc [2] 4a c0 [2] 46 ca [2] 51 c1 [2] 4a 8f [2] 77 }

  condition:
    any of them
}
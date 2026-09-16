rule TTP_XOR_MULT_DOSStub_d9af {
  strings:
    $key_d9af = { 8d c7 [2] f9 df [2] be dd [2] f9 cc [2] b7 c0 [2] bb ca [2] ac c1 [2] b7 8f [2] 8a }

  condition:
    any of them
}
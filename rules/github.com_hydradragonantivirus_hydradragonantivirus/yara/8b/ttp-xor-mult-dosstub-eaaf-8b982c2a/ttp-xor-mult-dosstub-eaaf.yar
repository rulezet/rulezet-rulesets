rule TTP_XOR_MULT_DOSStub_eaaf {
  strings:
    $key_eaaf = { be c7 [2] ca df [2] 8d dd [2] ca cc [2] 84 c0 [2] 88 ca [2] 9f c1 [2] 84 8f [2] b9 }

  condition:
    any of them
}
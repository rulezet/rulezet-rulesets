rule TTP_XOR_MULT_DOSStub_baaf {
  strings:
    $key_baaf = { ee c7 [2] 9a df [2] dd dd [2] 9a cc [2] d4 c0 [2] d8 ca [2] cf c1 [2] d4 8f [2] e9 }

  condition:
    any of them
}
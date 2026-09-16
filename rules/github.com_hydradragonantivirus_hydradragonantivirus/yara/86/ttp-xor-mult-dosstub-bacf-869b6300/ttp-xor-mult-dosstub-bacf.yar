rule TTP_XOR_MULT_DOSStub_bacf {
  strings:
    $key_bacf = { ee a7 [2] 9a bf [2] dd bd [2] 9a ac [2] d4 a0 [2] d8 aa [2] cf a1 [2] d4 ef [2] e9 }

  condition:
    any of them
}
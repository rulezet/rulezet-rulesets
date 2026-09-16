rule TTP_XOR_MULT_DOSStub_9bcf {
  strings:
    $key_9bcf = { cf a7 [2] bb bf [2] fc bd [2] bb ac [2] f5 a0 [2] f9 aa [2] ee a1 [2] f5 ef [2] c8 }

  condition:
    any of them
}
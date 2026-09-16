rule TTP_XOR_MULT_DOSStub_bacd {
  strings:
    $key_bacd = { ee a5 [2] 9a bd [2] dd bf [2] 9a ae [2] d4 a2 [2] d8 a8 [2] cf a3 [2] d4 ed [2] e9 }

  condition:
    any of them
}
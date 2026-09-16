rule TTP_XOR_MULT_DOSStub_8ccc {
  strings:
    $key_8ccc = { d8 a4 [2] ac bc [2] eb be [2] ac af [2] e2 a3 [2] ee a9 [2] f9 a2 [2] e2 ec [2] df }

  condition:
    any of them
}
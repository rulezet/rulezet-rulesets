rule TTP_XOR_MULT_DOSStub_dfcc {
  strings:
    $key_dfcc = { 8b a4 [2] ff bc [2] b8 be [2] ff af [2] b1 a3 [2] bd a9 [2] aa a2 [2] b1 ec [2] 8c }

  condition:
    any of them
}
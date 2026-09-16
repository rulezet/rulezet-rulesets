rule TTP_XOR_MULT_DOSStub_2ecc {
  strings:
    $key_2ecc = { 7a a4 [2] 0e bc [2] 49 be [2] 0e af [2] 40 a3 [2] 4c a9 [2] 5b a2 [2] 40 ec [2] 7d }

  condition:
    any of them
}
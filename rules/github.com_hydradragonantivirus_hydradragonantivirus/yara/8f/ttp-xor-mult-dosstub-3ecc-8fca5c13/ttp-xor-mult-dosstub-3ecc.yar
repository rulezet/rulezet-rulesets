rule TTP_XOR_MULT_DOSStub_3ecc {
  strings:
    $key_3ecc = { 6a a4 [2] 1e bc [2] 59 be [2] 1e af [2] 50 a3 [2] 5c a9 [2] 4b a2 [2] 50 ec [2] 6d }

  condition:
    any of them
}
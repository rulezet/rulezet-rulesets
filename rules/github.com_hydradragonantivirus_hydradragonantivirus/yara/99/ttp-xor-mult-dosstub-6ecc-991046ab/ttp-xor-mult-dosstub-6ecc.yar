rule TTP_XOR_MULT_DOSStub_6ecc {
  strings:
    $key_6ecc = { 3a a4 [2] 4e bc [2] 09 be [2] 4e af [2] 00 a3 [2] 0c a9 [2] 1b a2 [2] 00 ec [2] 3d }

  condition:
    any of them
}
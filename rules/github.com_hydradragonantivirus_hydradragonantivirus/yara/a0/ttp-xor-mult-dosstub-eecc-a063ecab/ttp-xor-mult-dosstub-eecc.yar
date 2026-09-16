rule TTP_XOR_MULT_DOSStub_eecc {
  strings:
    $key_eecc = { ba a4 [2] ce bc [2] 89 be [2] ce af [2] 80 a3 [2] 8c a9 [2] 9b a2 [2] 80 ec [2] bd }

  condition:
    any of them
}
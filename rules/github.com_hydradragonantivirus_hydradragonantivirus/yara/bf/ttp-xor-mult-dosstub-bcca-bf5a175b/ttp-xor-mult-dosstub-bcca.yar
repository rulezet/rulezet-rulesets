rule TTP_XOR_MULT_DOSStub_bcca {
  strings:
    $key_bcca = { e8 a2 [2] 9c ba [2] db b8 [2] 9c a9 [2] d2 a5 [2] de af [2] c9 a4 [2] d2 ea [2] ef }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_afb7 {
  strings:
    $key_afb7 = { fb df [2] 8f c7 [2] c8 c5 [2] 8f d4 [2] c1 d8 [2] cd d2 [2] da d9 [2] c1 97 [2] fc }

  condition:
    any of them
}
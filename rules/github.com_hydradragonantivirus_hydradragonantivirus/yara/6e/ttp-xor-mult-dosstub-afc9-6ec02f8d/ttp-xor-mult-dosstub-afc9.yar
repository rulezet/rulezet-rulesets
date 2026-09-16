rule TTP_XOR_MULT_DOSStub_afc9 {
  strings:
    $key_afc9 = { fb a1 [2] 8f b9 [2] c8 bb [2] 8f aa [2] c1 a6 [2] cd ac [2] da a7 [2] c1 e9 [2] fc }

  condition:
    any of them
}
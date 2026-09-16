rule TTP_XOR_MULT_DOSStub_afcf {
  strings:
    $key_afcf = { fb a7 [2] 8f bf [2] c8 bd [2] 8f ac [2] c1 a0 [2] cd aa [2] da a1 [2] c1 ef [2] fc }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_afea {
  strings:
    $key_afea = { fb 82 [2] 8f 9a [2] c8 98 [2] 8f 89 [2] c1 85 [2] cd 8f [2] da 84 [2] c1 ca [2] fc }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_afeb {
  strings:
    $key_afeb = { fb 83 [2] 8f 9b [2] c8 99 [2] 8f 88 [2] c1 84 [2] cd 8e [2] da 85 [2] c1 cb [2] fc }

  condition:
    any of them
}
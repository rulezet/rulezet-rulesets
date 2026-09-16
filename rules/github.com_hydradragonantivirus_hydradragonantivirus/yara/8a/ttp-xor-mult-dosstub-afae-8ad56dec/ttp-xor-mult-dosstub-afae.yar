rule TTP_XOR_MULT_DOSStub_afae {
  strings:
    $key_afae = { fb c6 [2] 8f de [2] c8 dc [2] 8f cd [2] c1 c1 [2] cd cb [2] da c0 [2] c1 8e [2] fc }

  condition:
    any of them
}
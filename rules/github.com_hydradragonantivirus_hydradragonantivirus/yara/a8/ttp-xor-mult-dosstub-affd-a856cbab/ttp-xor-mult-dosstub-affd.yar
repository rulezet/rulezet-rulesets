rule TTP_XOR_MULT_DOSStub_affd {
  strings:
    $key_affd = { fb 95 [2] 8f 8d [2] c8 8f [2] 8f 9e [2] c1 92 [2] cd 98 [2] da 93 [2] c1 dd [2] fc }

  condition:
    any of them
}
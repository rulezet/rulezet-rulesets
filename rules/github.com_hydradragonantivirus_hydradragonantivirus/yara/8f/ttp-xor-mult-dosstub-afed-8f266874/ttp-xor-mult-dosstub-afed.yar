rule TTP_XOR_MULT_DOSStub_afed {
  strings:
    $key_afed = { fb 85 [2] 8f 9d [2] c8 9f [2] 8f 8e [2] c1 82 [2] cd 88 [2] da 83 [2] c1 cd [2] fc }

  condition:
    any of them
}
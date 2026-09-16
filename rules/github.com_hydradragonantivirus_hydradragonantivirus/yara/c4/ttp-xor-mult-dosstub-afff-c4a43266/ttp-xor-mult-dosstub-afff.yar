rule TTP_XOR_MULT_DOSStub_afff {
  strings:
    $key_afff = { fb 97 [2] 8f 8f [2] c8 8d [2] 8f 9c [2] c1 90 [2] cd 9a [2] da 91 [2] c1 df [2] fc }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_af10 {
  strings:
    $key_af10 = { fb 78 [2] 8f 60 [2] c8 62 [2] 8f 73 [2] c1 7f [2] cd 75 [2] da 7e [2] c1 30 [2] fc }

  condition:
    any of them
}
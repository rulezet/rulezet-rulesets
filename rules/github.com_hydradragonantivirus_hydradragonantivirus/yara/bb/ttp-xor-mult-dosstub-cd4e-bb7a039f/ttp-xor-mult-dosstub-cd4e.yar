rule TTP_XOR_MULT_DOSStub_cd4e {
  strings:
    $key_cd4e = { 99 26 [2] ed 3e [2] aa 3c [2] ed 2d [2] a3 21 [2] af 2b [2] b8 20 [2] a3 6e [2] 9e }

  condition:
    any of them
}
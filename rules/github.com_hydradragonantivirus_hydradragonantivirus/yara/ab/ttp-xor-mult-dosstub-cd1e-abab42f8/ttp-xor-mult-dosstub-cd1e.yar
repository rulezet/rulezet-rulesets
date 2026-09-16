rule TTP_XOR_MULT_DOSStub_cd1e {
  strings:
    $key_cd1e = { 99 76 [2] ed 6e [2] aa 6c [2] ed 7d [2] a3 71 [2] af 7b [2] b8 70 [2] a3 3e [2] 9e }

  condition:
    any of them
}
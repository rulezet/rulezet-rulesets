rule TTP_XOR_MULT_DOSStub_cd5e {
  strings:
    $key_cd5e = { 99 36 [2] ed 2e [2] aa 2c [2] ed 3d [2] a3 31 [2] af 3b [2] b8 30 [2] a3 7e [2] 9e }

  condition:
    any of them
}
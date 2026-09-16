rule TTP_XOR_MULT_DOSStub_cd4d {
  strings:
    $key_cd4d = { 99 25 [2] ed 3d [2] aa 3f [2] ed 2e [2] a3 22 [2] af 28 [2] b8 23 [2] a3 6d [2] 9e }

  condition:
    any of them
}
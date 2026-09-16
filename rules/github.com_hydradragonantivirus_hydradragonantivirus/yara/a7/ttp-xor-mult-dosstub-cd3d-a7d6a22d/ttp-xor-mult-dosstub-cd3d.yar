rule TTP_XOR_MULT_DOSStub_cd3d {
  strings:
    $key_cd3d = { 99 55 [2] ed 4d [2] aa 4f [2] ed 5e [2] a3 52 [2] af 58 [2] b8 53 [2] a3 1d [2] 9e }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_cd2d {
  strings:
    $key_cd2d = { 99 45 [2] ed 5d [2] aa 5f [2] ed 4e [2] a3 42 [2] af 48 [2] b8 43 [2] a3 0d [2] 9e }

  condition:
    any of them
}
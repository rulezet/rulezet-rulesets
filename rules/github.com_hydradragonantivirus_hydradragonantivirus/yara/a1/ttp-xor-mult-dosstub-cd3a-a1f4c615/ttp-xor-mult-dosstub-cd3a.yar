rule TTP_XOR_MULT_DOSStub_cd3a {
  strings:
    $key_cd3a = { 99 52 [2] ed 4a [2] aa 48 [2] ed 59 [2] a3 55 [2] af 5f [2] b8 54 [2] a3 1a [2] 9e }

  condition:
    any of them
}
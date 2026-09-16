rule TTP_XOR_MULT_DOSStub_cd4a {
  strings:
    $key_cd4a = { 99 22 [2] ed 3a [2] aa 38 [2] ed 29 [2] a3 25 [2] af 2f [2] b8 24 [2] a3 6a [2] 9e }

  condition:
    any of them
}
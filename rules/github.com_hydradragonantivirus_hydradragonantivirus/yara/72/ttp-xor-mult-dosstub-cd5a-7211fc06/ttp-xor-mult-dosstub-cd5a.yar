rule TTP_XOR_MULT_DOSStub_cd5a {
  strings:
    $key_cd5a = { 99 32 [2] ed 2a [2] aa 28 [2] ed 39 [2] a3 35 [2] af 3f [2] b8 34 [2] a3 7a [2] 9e }

  condition:
    any of them
}
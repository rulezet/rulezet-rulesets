rule TTP_XOR_MULT_DOSStub_cd2a {
  strings:
    $key_cd2a = { 99 42 [2] ed 5a [2] aa 58 [2] ed 49 [2] a3 45 [2] af 4f [2] b8 44 [2] a3 0a [2] 9e }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_cd0a {
  strings:
    $key_cd0a = { 99 62 [2] ed 7a [2] aa 78 [2] ed 69 [2] a3 65 [2] af 6f [2] b8 64 [2] a3 2a [2] 9e }

  condition:
    any of them
}
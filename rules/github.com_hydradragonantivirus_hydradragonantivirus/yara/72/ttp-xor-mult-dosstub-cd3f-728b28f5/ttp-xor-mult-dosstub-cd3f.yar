rule TTP_XOR_MULT_DOSStub_cd3f {
  strings:
    $key_cd3f = { 99 57 [2] ed 4f [2] aa 4d [2] ed 5c [2] a3 50 [2] af 5a [2] b8 51 [2] a3 1f [2] 9e }

  condition:
    any of them
}
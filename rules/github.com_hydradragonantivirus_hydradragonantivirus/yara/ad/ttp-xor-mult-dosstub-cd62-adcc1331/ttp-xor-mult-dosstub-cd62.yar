rule TTP_XOR_MULT_DOSStub_cd62 {
  strings:
    $key_cd62 = { 99 0a [2] ed 12 [2] aa 10 [2] ed 01 [2] a3 0d [2] af 07 [2] b8 0c [2] a3 42 [2] 9e }

  condition:
    any of them
}
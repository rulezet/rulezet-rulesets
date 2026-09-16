rule TTP_XOR_MULT_DOSStub_cd25 {
  strings:
    $key_cd25 = { 99 4d [2] ed 55 [2] aa 57 [2] ed 46 [2] a3 4a [2] af 40 [2] b8 4b [2] a3 05 [2] 9e }

  condition:
    any of them
}
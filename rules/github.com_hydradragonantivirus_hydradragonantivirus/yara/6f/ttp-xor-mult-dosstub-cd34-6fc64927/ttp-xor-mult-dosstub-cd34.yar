rule TTP_XOR_MULT_DOSStub_cd34 {
  strings:
    $key_cd34 = { 99 5c [2] ed 44 [2] aa 46 [2] ed 57 [2] a3 5b [2] af 51 [2] b8 5a [2] a3 14 [2] 9e }

  condition:
    any of them
}
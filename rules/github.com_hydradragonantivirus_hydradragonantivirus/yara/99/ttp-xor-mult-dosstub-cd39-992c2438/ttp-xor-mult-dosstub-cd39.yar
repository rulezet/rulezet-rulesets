rule TTP_XOR_MULT_DOSStub_cd39 {
  strings:
    $key_cd39 = { 99 51 [2] ed 49 [2] aa 4b [2] ed 5a [2] a3 56 [2] af 5c [2] b8 57 [2] a3 19 [2] 9e }

  condition:
    any of them
}
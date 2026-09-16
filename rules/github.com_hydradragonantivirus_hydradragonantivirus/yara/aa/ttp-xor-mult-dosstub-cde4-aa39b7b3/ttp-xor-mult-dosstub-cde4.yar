rule TTP_XOR_MULT_DOSStub_cde4 {
  strings:
    $key_cde4 = { 99 8c [2] ed 94 [2] aa 96 [2] ed 87 [2] a3 8b [2] af 81 [2] b8 8a [2] a3 c4 [2] 9e }

  condition:
    any of them
}
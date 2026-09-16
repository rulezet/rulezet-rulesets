rule TTP_XOR_MULT_DOSStub_cd04 {
  strings:
    $key_cd04 = { 99 6c [2] ed 74 [2] aa 76 [2] ed 67 [2] a3 6b [2] af 61 [2] b8 6a [2] a3 24 [2] 9e }

  condition:
    any of them
}
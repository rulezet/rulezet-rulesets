rule TTP_XOR_MULT_DOSStub_cd08 {
  strings:
    $key_cd08 = { 99 60 [2] ed 78 [2] aa 7a [2] ed 6b [2] a3 67 [2] af 6d [2] b8 66 [2] a3 28 [2] 9e }

  condition:
    any of them
}
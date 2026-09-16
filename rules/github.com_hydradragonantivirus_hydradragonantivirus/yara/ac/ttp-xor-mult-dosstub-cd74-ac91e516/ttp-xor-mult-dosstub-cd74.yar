rule TTP_XOR_MULT_DOSStub_cd74 {
  strings:
    $key_cd74 = { 99 1c [2] ed 04 [2] aa 06 [2] ed 17 [2] a3 1b [2] af 11 [2] b8 1a [2] a3 54 [2] 9e }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_cd05 {
  strings:
    $key_cd05 = { 99 6d [2] ed 75 [2] aa 77 [2] ed 66 [2] a3 6a [2] af 60 [2] b8 6b [2] a3 25 [2] 9e }

  condition:
    any of them
}
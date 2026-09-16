rule TTP_XOR_MULT_DOSStub_cd35 {
  strings:
    $key_cd35 = { 99 5d [2] ed 45 [2] aa 47 [2] ed 56 [2] a3 5a [2] af 50 [2] b8 5b [2] a3 15 [2] 9e }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_cd46 {
  strings:
    $key_cd46 = { 99 2e [2] ed 36 [2] aa 34 [2] ed 25 [2] a3 29 [2] af 23 [2] b8 28 [2] a3 66 [2] 9e }

  condition:
    any of them
}
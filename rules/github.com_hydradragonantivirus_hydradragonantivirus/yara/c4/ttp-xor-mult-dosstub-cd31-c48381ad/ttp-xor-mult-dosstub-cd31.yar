rule TTP_XOR_MULT_DOSStub_cd31 {
  strings:
    $key_cd31 = { 99 59 [2] ed 41 [2] aa 43 [2] ed 52 [2] a3 5e [2] af 54 [2] b8 5f [2] a3 11 [2] 9e }

  condition:
    any of them
}
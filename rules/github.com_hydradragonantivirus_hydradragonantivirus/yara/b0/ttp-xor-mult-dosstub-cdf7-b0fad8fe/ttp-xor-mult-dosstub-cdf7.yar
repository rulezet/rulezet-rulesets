rule TTP_XOR_MULT_DOSStub_cdf7 {
  strings:
    $key_cdf7 = { 99 9f [2] ed 87 [2] aa 85 [2] ed 94 [2] a3 98 [2] af 92 [2] b8 99 [2] a3 d7 [2] 9e }

  condition:
    any of them
}
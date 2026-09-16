rule TTP_XOR_MULT_DOSStub_cdf6 {
  strings:
    $key_cdf6 = { 99 9e [2] ed 86 [2] aa 84 [2] ed 95 [2] a3 99 [2] af 93 [2] b8 98 [2] a3 d6 [2] 9e }

  condition:
    any of them
}
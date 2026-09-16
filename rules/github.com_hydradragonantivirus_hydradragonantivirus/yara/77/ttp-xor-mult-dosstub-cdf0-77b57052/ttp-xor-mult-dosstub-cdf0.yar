rule TTP_XOR_MULT_DOSStub_cdf0 {
  strings:
    $key_cdf0 = { 99 98 [2] ed 80 [2] aa 82 [2] ed 93 [2] a3 9f [2] af 95 [2] b8 9e [2] a3 d0 [2] 9e }

  condition:
    any of them
}
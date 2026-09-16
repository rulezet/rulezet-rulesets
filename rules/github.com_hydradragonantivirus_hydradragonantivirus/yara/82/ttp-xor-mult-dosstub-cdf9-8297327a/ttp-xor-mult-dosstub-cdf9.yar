rule TTP_XOR_MULT_DOSStub_cdf9 {
  strings:
    $key_cdf9 = { 99 91 [2] ed 89 [2] aa 8b [2] ed 9a [2] a3 96 [2] af 9c [2] b8 97 [2] a3 d9 [2] 9e }

  condition:
    any of them
}
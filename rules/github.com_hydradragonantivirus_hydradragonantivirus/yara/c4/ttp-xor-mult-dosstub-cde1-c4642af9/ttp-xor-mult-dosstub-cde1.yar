rule TTP_XOR_MULT_DOSStub_cde1 {
  strings:
    $key_cde1 = { 99 89 [2] ed 91 [2] aa 93 [2] ed 82 [2] a3 8e [2] af 84 [2] b8 8f [2] a3 c1 [2] 9e }

  condition:
    any of them
}
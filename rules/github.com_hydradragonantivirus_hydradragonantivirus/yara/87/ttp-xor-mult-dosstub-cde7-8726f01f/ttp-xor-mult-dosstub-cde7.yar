rule TTP_XOR_MULT_DOSStub_cde7 {
  strings:
    $key_cde7 = { 99 8f [2] ed 97 [2] aa 95 [2] ed 84 [2] a3 88 [2] af 82 [2] b8 89 [2] a3 c7 [2] 9e }

  condition:
    any of them
}
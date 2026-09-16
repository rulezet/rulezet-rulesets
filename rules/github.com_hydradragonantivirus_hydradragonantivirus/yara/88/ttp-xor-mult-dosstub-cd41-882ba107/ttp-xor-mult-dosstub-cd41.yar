rule TTP_XOR_MULT_DOSStub_cd41 {
  strings:
    $key_cd41 = { 99 29 [2] ed 31 [2] aa 33 [2] ed 22 [2] a3 2e [2] af 24 [2] b8 2f [2] a3 61 [2] 9e }

  condition:
    any of them
}
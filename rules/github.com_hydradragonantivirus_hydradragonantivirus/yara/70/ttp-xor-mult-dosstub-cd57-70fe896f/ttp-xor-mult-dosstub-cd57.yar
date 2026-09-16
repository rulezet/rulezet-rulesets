rule TTP_XOR_MULT_DOSStub_cd57 {
  strings:
    $key_cd57 = { 99 3f [2] ed 27 [2] aa 25 [2] ed 34 [2] a3 38 [2] af 32 [2] b8 39 [2] a3 77 [2] 9e }

  condition:
    any of them
}
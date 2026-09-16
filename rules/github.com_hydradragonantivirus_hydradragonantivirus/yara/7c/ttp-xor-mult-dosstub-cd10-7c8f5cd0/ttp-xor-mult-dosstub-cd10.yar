rule TTP_XOR_MULT_DOSStub_cd10 {
  strings:
    $key_cd10 = { 99 78 [2] ed 60 [2] aa 62 [2] ed 73 [2] a3 7f [2] af 75 [2] b8 7e [2] a3 30 [2] 9e }

  condition:
    any of them
}
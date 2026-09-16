rule TTP_XOR_MULT_DOSStub_cd26 {
  strings:
    $key_cd26 = { 99 4e [2] ed 56 [2] aa 54 [2] ed 45 [2] a3 49 [2] af 43 [2] b8 48 [2] a3 06 [2] 9e }

  condition:
    any of them
}
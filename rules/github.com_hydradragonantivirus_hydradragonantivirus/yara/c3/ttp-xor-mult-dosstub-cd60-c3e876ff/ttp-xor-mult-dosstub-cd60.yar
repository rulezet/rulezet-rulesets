rule TTP_XOR_MULT_DOSStub_cd60 {
  strings:
    $key_cd60 = { 99 08 [2] ed 10 [2] aa 12 [2] ed 03 [2] a3 0f [2] af 05 [2] b8 0e [2] a3 40 [2] 9e }

  condition:
    any of them
}
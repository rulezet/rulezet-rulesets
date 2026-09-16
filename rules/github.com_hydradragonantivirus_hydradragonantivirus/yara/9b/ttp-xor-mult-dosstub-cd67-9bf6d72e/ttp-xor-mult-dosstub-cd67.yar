rule TTP_XOR_MULT_DOSStub_cd67 {
  strings:
    $key_cd67 = { 99 0f [2] ed 17 [2] aa 15 [2] ed 04 [2] a3 08 [2] af 02 [2] b8 09 [2] a3 47 [2] 9e }

  condition:
    any of them
}
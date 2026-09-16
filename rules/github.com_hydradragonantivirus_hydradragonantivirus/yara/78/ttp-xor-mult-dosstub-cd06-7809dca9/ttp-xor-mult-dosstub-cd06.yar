rule TTP_XOR_MULT_DOSStub_cd06 {
  strings:
    $key_cd06 = { 99 6e [2] ed 76 [2] aa 74 [2] ed 65 [2] a3 69 [2] af 63 [2] b8 68 [2] a3 26 [2] 9e }

  condition:
    any of them
}
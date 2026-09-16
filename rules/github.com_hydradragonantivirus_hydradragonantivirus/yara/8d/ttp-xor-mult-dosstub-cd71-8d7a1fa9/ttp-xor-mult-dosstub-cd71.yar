rule TTP_XOR_MULT_DOSStub_cd71 {
  strings:
    $key_cd71 = { 99 19 [2] ed 01 [2] aa 03 [2] ed 12 [2] a3 1e [2] af 14 [2] b8 1f [2] a3 51 [2] 9e }

  condition:
    any of them
}
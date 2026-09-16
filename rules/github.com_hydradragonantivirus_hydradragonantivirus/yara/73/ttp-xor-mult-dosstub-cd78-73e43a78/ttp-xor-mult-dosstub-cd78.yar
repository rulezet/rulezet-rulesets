rule TTP_XOR_MULT_DOSStub_cd78 {
  strings:
    $key_cd78 = { 99 10 [2] ed 08 [2] aa 0a [2] ed 1b [2] a3 17 [2] af 1d [2] b8 16 [2] a3 58 [2] 9e }

  condition:
    any of them
}
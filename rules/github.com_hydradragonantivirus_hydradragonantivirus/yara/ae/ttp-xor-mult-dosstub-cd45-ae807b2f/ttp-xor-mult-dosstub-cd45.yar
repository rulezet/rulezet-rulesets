rule TTP_XOR_MULT_DOSStub_cd45 {
  strings:
    $key_cd45 = { 99 2d [2] ed 35 [2] aa 37 [2] ed 26 [2] a3 2a [2] af 20 [2] b8 2b [2] a3 65 [2] 9e }

  condition:
    any of them
}
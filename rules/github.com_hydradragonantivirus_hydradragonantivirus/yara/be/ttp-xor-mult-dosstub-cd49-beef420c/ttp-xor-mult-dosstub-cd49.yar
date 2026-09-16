rule TTP_XOR_MULT_DOSStub_cd49 {
  strings:
    $key_cd49 = { 99 21 [2] ed 39 [2] aa 3b [2] ed 2a [2] a3 26 [2] af 2c [2] b8 27 [2] a3 69 [2] 9e }

  condition:
    any of them
}
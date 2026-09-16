rule TTP_XOR_MULT_DOSStub_cd24 {
  strings:
    $key_cd24 = { 99 4c [2] ed 54 [2] aa 56 [2] ed 47 [2] a3 4b [2] af 41 [2] b8 4a [2] a3 04 [2] 9e }

  condition:
    any of them
}
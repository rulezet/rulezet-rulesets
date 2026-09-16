rule TTP_XOR_MULT_DOSStub_cd64 {
  strings:
    $key_cd64 = { 99 0c [2] ed 14 [2] aa 16 [2] ed 07 [2] a3 0b [2] af 01 [2] b8 0a [2] a3 44 [2] 9e }

  condition:
    any of them
}
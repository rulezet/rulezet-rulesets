rule TTP_XOR_MULT_DOSStub_cd21 {
  strings:
    $key_cd21 = { 99 49 [2] ed 51 [2] aa 53 [2] ed 42 [2] a3 4e [2] af 44 [2] b8 4f [2] a3 01 [2] 9e }

  condition:
    any of them
}
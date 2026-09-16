rule TTP_XOR_MULT_DOSStub_cd1b {
  strings:
    $key_cd1b = { 99 73 [2] ed 6b [2] aa 69 [2] ed 78 [2] a3 74 [2] af 7e [2] b8 75 [2] a3 3b [2] 9e }

  condition:
    any of them
}
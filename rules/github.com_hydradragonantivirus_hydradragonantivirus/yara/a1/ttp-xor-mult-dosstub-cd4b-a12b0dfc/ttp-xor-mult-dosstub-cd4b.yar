rule TTP_XOR_MULT_DOSStub_cd4b {
  strings:
    $key_cd4b = { 99 23 [2] ed 3b [2] aa 39 [2] ed 28 [2] a3 24 [2] af 2e [2] b8 25 [2] a3 6b [2] 9e }

  condition:
    any of them
}
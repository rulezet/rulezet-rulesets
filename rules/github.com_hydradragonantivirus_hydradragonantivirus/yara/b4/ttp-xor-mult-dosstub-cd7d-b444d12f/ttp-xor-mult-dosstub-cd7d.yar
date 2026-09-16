rule TTP_XOR_MULT_DOSStub_cd7d {
  strings:
    $key_cd7d = { 99 15 [2] ed 0d [2] aa 0f [2] ed 1e [2] a3 12 [2] af 18 [2] b8 13 [2] a3 5d [2] 9e }

  condition:
    any of them
}
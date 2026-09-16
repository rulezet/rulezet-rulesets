rule TTP_XOR_MULT_DOSStub_cd6e {
  strings:
    $key_cd6e = { 99 06 [2] ed 1e [2] aa 1c [2] ed 0d [2] a3 01 [2] af 0b [2] b8 00 [2] a3 4e [2] 9e }

  condition:
    any of them
}
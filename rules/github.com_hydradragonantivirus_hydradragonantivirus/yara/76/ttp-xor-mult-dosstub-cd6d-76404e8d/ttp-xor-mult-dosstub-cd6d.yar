rule TTP_XOR_MULT_DOSStub_cd6d {
  strings:
    $key_cd6d = { 99 05 [2] ed 1d [2] aa 1f [2] ed 0e [2] a3 02 [2] af 08 [2] b8 03 [2] a3 4d [2] 9e }

  condition:
    any of them
}
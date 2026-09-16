rule TTP_XOR_MULT_DOSStub_cd6f {
  strings:
    $key_cd6f = { 99 07 [2] ed 1f [2] aa 1d [2] ed 0c [2] a3 00 [2] af 0a [2] b8 01 [2] a3 4f [2] 9e }

  condition:
    any of them
}
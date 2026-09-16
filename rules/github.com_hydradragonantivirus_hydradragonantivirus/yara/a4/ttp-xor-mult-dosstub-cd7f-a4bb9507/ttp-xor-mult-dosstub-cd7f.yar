rule TTP_XOR_MULT_DOSStub_cd7f {
  strings:
    $key_cd7f = { 99 17 [2] ed 0f [2] aa 0d [2] ed 1c [2] a3 10 [2] af 1a [2] b8 11 [2] a3 5f [2] 9e }

  condition:
    any of them
}
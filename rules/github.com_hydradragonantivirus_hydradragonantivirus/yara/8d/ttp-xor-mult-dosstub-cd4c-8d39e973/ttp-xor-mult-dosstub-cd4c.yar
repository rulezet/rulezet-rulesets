rule TTP_XOR_MULT_DOSStub_cd4c {
  strings:
    $key_cd4c = { 99 24 [2] ed 3c [2] aa 3e [2] ed 2f [2] a3 23 [2] af 29 [2] b8 22 [2] a3 6c [2] 9e }

  condition:
    any of them
}
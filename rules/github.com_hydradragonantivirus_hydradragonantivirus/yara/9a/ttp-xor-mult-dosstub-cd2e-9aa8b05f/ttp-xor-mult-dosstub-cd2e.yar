rule TTP_XOR_MULT_DOSStub_cd2e {
  strings:
    $key_cd2e = { 99 46 [2] ed 5e [2] aa 5c [2] ed 4d [2] a3 41 [2] af 4b [2] b8 40 [2] a3 0e [2] 9e }

  condition:
    any of them
}
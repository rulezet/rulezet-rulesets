rule TTP_XOR_MULT_DOSStub_cd0e {
  strings:
    $key_cd0e = { 99 66 [2] ed 7e [2] aa 7c [2] ed 6d [2] a3 61 [2] af 6b [2] b8 60 [2] a3 2e [2] 9e }

  condition:
    any of them
}
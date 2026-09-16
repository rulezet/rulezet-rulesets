rule TTP_XOR_MULT_DOSStub_fa0e {
  strings:
    $key_fa0e = { ae 66 [2] da 7e [2] 9d 7c [2] da 6d [2] 94 61 [2] 98 6b [2] 8f 60 [2] 94 2e [2] a9 }

  condition:
    any of them
}
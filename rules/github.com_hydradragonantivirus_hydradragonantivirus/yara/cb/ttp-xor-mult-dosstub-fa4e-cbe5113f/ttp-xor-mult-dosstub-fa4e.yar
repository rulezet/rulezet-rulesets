rule TTP_XOR_MULT_DOSStub_fa4e {
  strings:
    $key_fa4e = { ae 26 [2] da 3e [2] 9d 3c [2] da 2d [2] 94 21 [2] 98 2b [2] 8f 20 [2] 94 6e [2] a9 }

  condition:
    any of them
}
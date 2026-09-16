rule TTP_XOR_MULT_DOSStub_fa2b {
  strings:
    $key_fa2b = { ae 43 [2] da 5b [2] 9d 59 [2] da 48 [2] 94 44 [2] 98 4e [2] 8f 45 [2] 94 0b [2] a9 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_fa3b {
  strings:
    $key_fa3b = { ae 53 [2] da 4b [2] 9d 49 [2] da 58 [2] 94 54 [2] 98 5e [2] 8f 55 [2] 94 1b [2] a9 }

  condition:
    any of them
}
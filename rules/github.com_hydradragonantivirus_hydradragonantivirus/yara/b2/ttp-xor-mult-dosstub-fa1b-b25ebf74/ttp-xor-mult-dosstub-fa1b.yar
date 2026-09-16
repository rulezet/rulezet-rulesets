rule TTP_XOR_MULT_DOSStub_fa1b {
  strings:
    $key_fa1b = { ae 73 [2] da 6b [2] 9d 69 [2] da 78 [2] 94 74 [2] 98 7e [2] 8f 75 [2] 94 3b [2] a9 }

  condition:
    any of them
}
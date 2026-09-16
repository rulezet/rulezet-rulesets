rule TTP_XOR_MULT_DOSStub_fa6b {
  strings:
    $key_fa6b = { ae 03 [2] da 1b [2] 9d 19 [2] da 08 [2] 94 04 [2] 98 0e [2] 8f 05 [2] 94 4b [2] a9 }

  condition:
    any of them
}
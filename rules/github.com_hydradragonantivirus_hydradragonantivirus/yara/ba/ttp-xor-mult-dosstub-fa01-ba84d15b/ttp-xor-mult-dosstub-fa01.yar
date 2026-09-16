rule TTP_XOR_MULT_DOSStub_fa01 {
  strings:
    $key_fa01 = { ae 69 [2] da 71 [2] 9d 73 [2] da 62 [2] 94 6e [2] 98 64 [2] 8f 6f [2] 94 21 [2] a9 }

  condition:
    any of them
}
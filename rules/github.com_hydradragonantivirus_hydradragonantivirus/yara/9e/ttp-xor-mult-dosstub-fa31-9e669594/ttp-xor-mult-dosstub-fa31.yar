rule TTP_XOR_MULT_DOSStub_fa31 {
  strings:
    $key_fa31 = { ae 59 [2] da 41 [2] 9d 43 [2] da 52 [2] 94 5e [2] 98 54 [2] 8f 5f [2] 94 11 [2] a9 }

  condition:
    any of them
}
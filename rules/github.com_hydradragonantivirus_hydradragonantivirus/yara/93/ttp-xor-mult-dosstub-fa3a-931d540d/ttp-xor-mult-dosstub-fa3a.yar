rule TTP_XOR_MULT_DOSStub_fa3a {
  strings:
    $key_fa3a = { ae 52 [2] da 4a [2] 9d 48 [2] da 59 [2] 94 55 [2] 98 5f [2] 8f 54 [2] 94 1a [2] a9 }

  condition:
    any of them
}
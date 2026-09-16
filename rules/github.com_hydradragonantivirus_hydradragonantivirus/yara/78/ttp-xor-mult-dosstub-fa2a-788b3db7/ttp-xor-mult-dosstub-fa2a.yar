rule TTP_XOR_MULT_DOSStub_fa2a {
  strings:
    $key_fa2a = { ae 42 [2] da 5a [2] 9d 58 [2] da 49 [2] 94 45 [2] 98 4f [2] 8f 44 [2] 94 0a [2] a9 }

  condition:
    any of them
}
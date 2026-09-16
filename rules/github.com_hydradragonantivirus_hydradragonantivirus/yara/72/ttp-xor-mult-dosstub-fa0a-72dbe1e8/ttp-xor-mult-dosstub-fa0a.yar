rule TTP_XOR_MULT_DOSStub_fa0a {
  strings:
    $key_fa0a = { ae 62 [2] da 7a [2] 9d 78 [2] da 69 [2] 94 65 [2] 98 6f [2] 8f 64 [2] 94 2a [2] a9 }

  condition:
    any of them
}
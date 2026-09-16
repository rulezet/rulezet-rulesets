rule TTP_XOR_MULT_DOSStub_fa3f {
  strings:
    $key_fa3f = { ae 57 [2] da 4f [2] 9d 4d [2] da 5c [2] 94 50 [2] 98 5a [2] 8f 51 [2] 94 1f [2] a9 }

  condition:
    any of them
}
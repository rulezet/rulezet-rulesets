rule TTP_XOR_MULT_DOSStub_fa6a {
  strings:
    $key_fa6a = { ae 02 [2] da 1a [2] 9d 18 [2] da 09 [2] 94 05 [2] 98 0f [2] 8f 04 [2] 94 4a [2] a9 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_fa28 {
  strings:
    $key_fa28 = { ae 40 [2] da 58 [2] 9d 5a [2] da 4b [2] 94 47 [2] 98 4d [2] 8f 46 [2] 94 08 [2] a9 }

  condition:
    any of them
}
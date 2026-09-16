rule TTP_XOR_MULT_DOSStub_fa04 {
  strings:
    $key_fa04 = { ae 6c [2] da 74 [2] 9d 76 [2] da 67 [2] 94 6b [2] 98 61 [2] 8f 6a [2] 94 24 [2] a9 }

  condition:
    any of them
}
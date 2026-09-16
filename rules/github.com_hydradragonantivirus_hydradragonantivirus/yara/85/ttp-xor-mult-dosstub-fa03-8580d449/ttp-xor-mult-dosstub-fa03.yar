rule TTP_XOR_MULT_DOSStub_fa03 {
  strings:
    $key_fa03 = { ae 6b [2] da 73 [2] 9d 71 [2] da 60 [2] 94 6c [2] 98 66 [2] 8f 6d [2] 94 23 [2] a9 }

  condition:
    any of them
}
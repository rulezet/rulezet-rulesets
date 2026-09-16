rule TTP_XOR_MULT_DOSStub_fa43 {
  strings:
    $key_fa43 = { ae 2b [2] da 33 [2] 9d 31 [2] da 20 [2] 94 2c [2] 98 26 [2] 8f 2d [2] 94 63 [2] a9 }

  condition:
    any of them
}
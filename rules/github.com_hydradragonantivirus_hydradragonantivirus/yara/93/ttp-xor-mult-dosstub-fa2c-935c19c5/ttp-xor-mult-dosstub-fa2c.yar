rule TTP_XOR_MULT_DOSStub_fa2c {
  strings:
    $key_fa2c = { ae 44 [2] da 5c [2] 9d 5e [2] da 4f [2] 94 43 [2] 98 49 [2] 8f 42 [2] 94 0c [2] a9 }

  condition:
    any of them
}
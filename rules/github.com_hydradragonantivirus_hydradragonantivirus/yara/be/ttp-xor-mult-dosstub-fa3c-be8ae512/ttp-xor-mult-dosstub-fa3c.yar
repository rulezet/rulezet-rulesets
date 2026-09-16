rule TTP_XOR_MULT_DOSStub_fa3c {
  strings:
    $key_fa3c = { ae 54 [2] da 4c [2] 9d 4e [2] da 5f [2] 94 53 [2] 98 59 [2] 8f 52 [2] 94 1c [2] a9 }

  condition:
    any of them
}
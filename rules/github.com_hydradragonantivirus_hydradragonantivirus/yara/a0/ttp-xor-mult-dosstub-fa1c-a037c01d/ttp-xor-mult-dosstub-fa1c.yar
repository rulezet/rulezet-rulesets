rule TTP_XOR_MULT_DOSStub_fa1c {
  strings:
    $key_fa1c = { ae 74 [2] da 6c [2] 9d 6e [2] da 7f [2] 94 73 [2] 98 79 [2] 8f 72 [2] 94 3c [2] a9 }

  condition:
    any of them
}
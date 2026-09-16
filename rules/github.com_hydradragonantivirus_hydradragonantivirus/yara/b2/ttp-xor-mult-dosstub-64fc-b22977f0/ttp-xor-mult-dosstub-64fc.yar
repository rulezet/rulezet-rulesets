rule TTP_XOR_MULT_DOSStub_64fc {
  strings:
    $key_64fc = { 30 94 [2] 44 8c [2] 03 8e [2] 44 9f [2] 0a 93 [2] 06 99 [2] 11 92 [2] 0a dc [2] 37 }

  condition:
    any of them
}
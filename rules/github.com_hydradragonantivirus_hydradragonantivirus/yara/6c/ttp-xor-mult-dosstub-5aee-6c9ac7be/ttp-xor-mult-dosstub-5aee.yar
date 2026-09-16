rule TTP_XOR_MULT_DOSStub_5aee {
  strings:
    $key_5aee = { 0e 86 [2] 7a 9e [2] 3d 9c [2] 7a 8d [2] 34 81 [2] 38 8b [2] 2f 80 [2] 34 ce [2] 09 }

  condition:
    any of them
}
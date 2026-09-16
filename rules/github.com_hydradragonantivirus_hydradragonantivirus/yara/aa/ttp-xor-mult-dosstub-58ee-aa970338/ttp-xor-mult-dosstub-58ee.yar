rule TTP_XOR_MULT_DOSStub_58ee {
  strings:
    $key_58ee = { 0c 86 [2] 78 9e [2] 3f 9c [2] 78 8d [2] 36 81 [2] 3a 8b [2] 2d 80 [2] 36 ce [2] 0b }

  condition:
    any of them
}
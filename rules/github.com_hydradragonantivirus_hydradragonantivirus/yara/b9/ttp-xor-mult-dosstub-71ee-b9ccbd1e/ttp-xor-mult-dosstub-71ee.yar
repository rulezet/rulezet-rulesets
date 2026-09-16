rule TTP_XOR_MULT_DOSStub_71ee {
  strings:
    $key_71ee = { 25 86 [2] 51 9e [2] 16 9c [2] 51 8d [2] 1f 81 [2] 13 8b [2] 04 80 [2] 1f ce [2] 22 }

  condition:
    any of them
}
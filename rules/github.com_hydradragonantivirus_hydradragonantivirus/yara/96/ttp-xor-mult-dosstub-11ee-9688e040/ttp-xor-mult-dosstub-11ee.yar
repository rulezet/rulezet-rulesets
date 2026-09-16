rule TTP_XOR_MULT_DOSStub_11ee {
  strings:
    $key_11ee = { 45 86 [2] 31 9e [2] 76 9c [2] 31 8d [2] 7f 81 [2] 73 8b [2] 64 80 [2] 7f ce [2] 42 }

  condition:
    any of them
}
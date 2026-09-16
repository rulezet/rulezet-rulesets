rule TTP_XOR_MULT_DOSStub_e7ee {
  strings:
    $key_e7ee = { b3 86 [2] c7 9e [2] 80 9c [2] c7 8d [2] 89 81 [2] 85 8b [2] 92 80 [2] 89 ce [2] b4 }

  condition:
    any of them
}
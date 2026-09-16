rule TTP_XOR_MULT_DOSStub_61ee {
  strings:
    $key_61ee = { 35 86 [2] 41 9e [2] 06 9c [2] 41 8d [2] 0f 81 [2] 03 8b [2] 14 80 [2] 0f ce [2] 32 }

  condition:
    any of them
}
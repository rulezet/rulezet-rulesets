rule TTP_XOR_MULT_DOSStub_68ee {
  strings:
    $key_68ee = { 3c 86 [2] 48 9e [2] 0f 9c [2] 48 8d [2] 06 81 [2] 0a 8b [2] 1d 80 [2] 06 ce [2] 3b }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_12ee {
  strings:
    $key_12ee = { 46 86 [2] 32 9e [2] 75 9c [2] 32 8d [2] 7c 81 [2] 70 8b [2] 67 80 [2] 7c ce [2] 41 }

  condition:
    any of them
}
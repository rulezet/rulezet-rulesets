rule TTP_XOR_MULT_DOSStub_42ee {
  strings:
    $key_42ee = { 16 86 [2] 62 9e [2] 25 9c [2] 62 8d [2] 2c 81 [2] 20 8b [2] 37 80 [2] 2c ce [2] 11 }

  condition:
    any of them
}
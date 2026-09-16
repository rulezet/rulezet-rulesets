rule TTP_XOR_MULT_DOSStub_665e {
  strings:
    $key_665e = { 32 36 [2] 46 2e [2] 01 2c [2] 46 3d [2] 08 31 [2] 04 3b [2] 13 30 [2] 08 7e [2] 35 }

  condition:
    any of them
}
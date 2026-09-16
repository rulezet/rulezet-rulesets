rule TTP_XOR_MULT_DOSStub_426c {
  strings:
    $key_426c = { 16 04 [2] 62 1c [2] 25 1e [2] 62 0f [2] 2c 03 [2] 20 09 [2] 37 02 [2] 2c 4c [2] 11 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_665c {
  strings:
    $key_665c = { 32 34 [2] 46 2c [2] 01 2e [2] 46 3f [2] 08 33 [2] 04 39 [2] 13 32 [2] 08 7c [2] 35 }

  condition:
    any of them
}
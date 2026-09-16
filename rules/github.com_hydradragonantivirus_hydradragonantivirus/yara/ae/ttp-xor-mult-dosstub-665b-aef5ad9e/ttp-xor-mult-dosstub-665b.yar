rule TTP_XOR_MULT_DOSStub_665b {
  strings:
    $key_665b = { 32 33 [2] 46 2b [2] 01 29 [2] 46 38 [2] 08 34 [2] 04 3e [2] 13 35 [2] 08 7b [2] 35 }

  condition:
    any of them
}
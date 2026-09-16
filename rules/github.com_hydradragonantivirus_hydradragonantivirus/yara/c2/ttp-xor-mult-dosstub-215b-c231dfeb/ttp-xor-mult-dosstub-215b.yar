rule TTP_XOR_MULT_DOSStub_215b {
  strings:
    $key_215b = { 75 33 [2] 01 2b [2] 46 29 [2] 01 38 [2] 4f 34 [2] 43 3e [2] 54 35 [2] 4f 7b [2] 72 }

  condition:
    any of them
}
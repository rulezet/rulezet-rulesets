rule TTP_XOR_MULT_DOSStub_3abf {
  strings:
    $key_3abf = { 6e d7 [2] 1a cf [2] 5d cd [2] 1a dc [2] 54 d0 [2] 58 da [2] 4f d1 [2] 54 9f [2] 69 }

  condition:
    any of them
}
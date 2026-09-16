rule TTP_XOR_MULT_DOSStub_1abf {
  strings:
    $key_1abf = { 4e d7 [2] 3a cf [2] 7d cd [2] 3a dc [2] 74 d0 [2] 78 da [2] 6f d1 [2] 74 9f [2] 49 }

  condition:
    any of them
}
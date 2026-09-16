rule TTP_XOR_MULT_DOSStub_7abf {
  strings:
    $key_7abf = { 2e d7 [2] 5a cf [2] 1d cd [2] 5a dc [2] 14 d0 [2] 18 da [2] 0f d1 [2] 14 9f [2] 29 }

  condition:
    any of them
}
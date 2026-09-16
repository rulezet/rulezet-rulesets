rule TTP_XOR_MULT_DOSStub_2abf {
  strings:
    $key_2abf = { 7e d7 [2] 0a cf [2] 4d cd [2] 0a dc [2] 44 d0 [2] 48 da [2] 5f d1 [2] 44 9f [2] 79 }

  condition:
    any of them
}
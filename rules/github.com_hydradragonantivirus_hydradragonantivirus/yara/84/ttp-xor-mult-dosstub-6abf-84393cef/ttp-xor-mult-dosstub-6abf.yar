rule TTP_XOR_MULT_DOSStub_6abf {
  strings:
    $key_6abf = { 3e d7 [2] 4a cf [2] 0d cd [2] 4a dc [2] 04 d0 [2] 08 da [2] 1f d1 [2] 04 9f [2] 39 }

  condition:
    any of them
}
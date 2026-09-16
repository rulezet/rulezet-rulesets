rule TTP_XOR_MULT_DOSStub_5abf {
  strings:
    $key_5abf = { 0e d7 [2] 7a cf [2] 3d cd [2] 7a dc [2] 34 d0 [2] 38 da [2] 2f d1 [2] 34 9f [2] 09 }

  condition:
    any of them
}
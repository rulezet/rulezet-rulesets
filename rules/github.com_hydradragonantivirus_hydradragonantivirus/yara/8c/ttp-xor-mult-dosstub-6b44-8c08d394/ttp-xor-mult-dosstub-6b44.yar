rule TTP_XOR_MULT_DOSStub_6b44 {
  strings:
    $key_6b44 = { 3f 2c [2] 4b 34 [2] 0c 36 [2] 4b 27 [2] 05 2b [2] 09 21 [2] 1e 2a [2] 05 64 [2] 38 }

  condition:
    any of them
}
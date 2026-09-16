rule TTP_XOR_MULT_DOSStub_6b48 {
  strings:
    $key_6b48 = { 3f 20 [2] 4b 38 [2] 0c 3a [2] 4b 2b [2] 05 27 [2] 09 2d [2] 1e 26 [2] 05 68 [2] 38 }

  condition:
    any of them
}
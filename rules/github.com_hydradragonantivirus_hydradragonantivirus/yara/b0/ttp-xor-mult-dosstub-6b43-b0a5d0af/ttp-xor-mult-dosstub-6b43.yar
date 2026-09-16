rule TTP_XOR_MULT_DOSStub_6b43 {
  strings:
    $key_6b43 = { 3f 2b [2] 4b 33 [2] 0c 31 [2] 4b 20 [2] 05 2c [2] 09 26 [2] 1e 2d [2] 05 63 [2] 38 }

  condition:
    any of them
}
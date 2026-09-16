rule TTP_XOR_MULT_DOSStub_1a43 {
  strings:
    $key_1a43 = { 4e 2b [2] 3a 33 [2] 7d 31 [2] 3a 20 [2] 74 2c [2] 78 26 [2] 6f 2d [2] 74 63 [2] 49 }

  condition:
    any of them
}
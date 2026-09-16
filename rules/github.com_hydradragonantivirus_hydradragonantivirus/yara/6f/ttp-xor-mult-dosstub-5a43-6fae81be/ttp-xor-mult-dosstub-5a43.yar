rule TTP_XOR_MULT_DOSStub_5a43 {
  strings:
    $key_5a43 = { 0e 2b [2] 7a 33 [2] 3d 31 [2] 7a 20 [2] 34 2c [2] 38 26 [2] 2f 2d [2] 34 63 [2] 09 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_6a43 {
  strings:
    $key_6a43 = { 3e 2b [2] 4a 33 [2] 0d 31 [2] 4a 20 [2] 04 2c [2] 08 26 [2] 1f 2d [2] 04 63 [2] 39 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_0a43 {
  strings:
    $key_0a43 = { 5e 2b [2] 2a 33 [2] 6d 31 [2] 2a 20 [2] 64 2c [2] 68 26 [2] 7f 2d [2] 64 63 [2] 59 }

  condition:
    any of them
}
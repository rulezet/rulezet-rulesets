rule TTP_XOR_MULT_DOSStub_5a73 {
  strings:
    $key_5a73 = { 0e 1b [2] 7a 03 [2] 3d 01 [2] 7a 10 [2] 34 1c [2] 38 16 [2] 2f 1d [2] 34 53 [2] 09 }

  condition:
    any of them
}
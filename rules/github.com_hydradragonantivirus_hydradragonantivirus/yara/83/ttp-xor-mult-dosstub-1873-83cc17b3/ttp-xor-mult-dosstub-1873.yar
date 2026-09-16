rule TTP_XOR_MULT_DOSStub_1873 {
  strings:
    $key_1873 = { 4c 1b [2] 38 03 [2] 7f 01 [2] 38 10 [2] 76 1c [2] 7a 16 [2] 6d 1d [2] 76 53 [2] 4b }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_1a73 {
  strings:
    $key_1a73 = { 4e 1b [2] 3a 03 [2] 7d 01 [2] 3a 10 [2] 74 1c [2] 78 16 [2] 6f 1d [2] 74 53 [2] 49 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_2a73 {
  strings:
    $key_2a73 = { 7e 1b [2] 0a 03 [2] 4d 01 [2] 0a 10 [2] 44 1c [2] 48 16 [2] 5f 1d [2] 44 53 [2] 79 }

  condition:
    any of them
}
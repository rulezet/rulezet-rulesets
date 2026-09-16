rule TTP_XOR_MULT_DOSStub_3973 {
  strings:
    $key_3973 = { 6d 1b [2] 19 03 [2] 5e 01 [2] 19 10 [2] 57 1c [2] 5b 16 [2] 4c 1d [2] 57 53 [2] 6a }

  condition:
    any of them
}
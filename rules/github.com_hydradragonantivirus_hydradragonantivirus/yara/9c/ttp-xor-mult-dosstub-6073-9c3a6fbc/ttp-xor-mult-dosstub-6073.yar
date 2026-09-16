rule TTP_XOR_MULT_DOSStub_6073 {
  strings:
    $key_6073 = { 34 1b [2] 40 03 [2] 07 01 [2] 40 10 [2] 0e 1c [2] 02 16 [2] 15 1d [2] 0e 53 [2] 33 }

  condition:
    any of them
}
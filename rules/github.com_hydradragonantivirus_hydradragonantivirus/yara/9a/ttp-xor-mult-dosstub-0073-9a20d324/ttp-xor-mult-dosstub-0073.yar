rule TTP_XOR_MULT_DOSStub_0073 {
  strings:
    $key_0073 = { 54 1b [2] 20 03 [2] 67 01 [2] 20 10 [2] 6e 1c [2] 62 16 [2] 75 1d [2] 6e 53 [2] 53 }

  condition:
    any of them
}
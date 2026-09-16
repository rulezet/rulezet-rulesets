rule TTP_XOR_MULT_DOSStub_004e {
  strings:
    $key_004e = { 54 26 [2] 20 3e [2] 67 3c [2] 20 2d [2] 6e 21 [2] 62 2b [2] 75 20 [2] 6e 6e [2] 53 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_545e {
  strings:
    $key_545e = { 00 36 [2] 74 2e [2] 33 2c [2] 74 3d [2] 3a 31 [2] 36 3b [2] 21 30 [2] 3a 7e [2] 07 }

  condition:
    any of them
}
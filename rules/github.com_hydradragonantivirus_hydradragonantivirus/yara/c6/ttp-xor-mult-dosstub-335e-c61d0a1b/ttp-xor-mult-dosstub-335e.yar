rule TTP_XOR_MULT_DOSStub_335e {
  strings:
    $key_335e = { 67 36 [2] 13 2e [2] 54 2c [2] 13 3d [2] 5d 31 [2] 51 3b [2] 46 30 [2] 5d 7e [2] 60 }

  condition:
    any of them
}
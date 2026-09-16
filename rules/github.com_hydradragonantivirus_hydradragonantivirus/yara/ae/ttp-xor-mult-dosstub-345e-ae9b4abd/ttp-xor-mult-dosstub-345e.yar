rule TTP_XOR_MULT_DOSStub_345e {
  strings:
    $key_345e = { 60 36 [2] 14 2e [2] 53 2c [2] 14 3d [2] 5a 31 [2] 56 3b [2] 41 30 [2] 5a 7e [2] 67 }

  condition:
    any of them
}
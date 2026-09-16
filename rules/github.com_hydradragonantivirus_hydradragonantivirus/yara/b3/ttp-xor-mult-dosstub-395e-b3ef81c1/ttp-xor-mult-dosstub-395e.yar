rule TTP_XOR_MULT_DOSStub_395e {
  strings:
    $key_395e = { 6d 36 [2] 19 2e [2] 5e 2c [2] 19 3d [2] 57 31 [2] 5b 3b [2] 4c 30 [2] 57 7e [2] 6a }

  condition:
    any of them
}
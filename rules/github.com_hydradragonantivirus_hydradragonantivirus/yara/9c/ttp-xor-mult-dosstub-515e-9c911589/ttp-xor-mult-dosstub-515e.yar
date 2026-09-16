rule TTP_XOR_MULT_DOSStub_515e {
  strings:
    $key_515e = { 05 36 [2] 71 2e [2] 36 2c [2] 71 3d [2] 3f 31 [2] 33 3b [2] 24 30 [2] 3f 7e [2] 02 }

  condition:
    any of them
}
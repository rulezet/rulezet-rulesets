rule TTP_XOR_MULT_DOSStub_115e {
  strings:
    $key_115e = { 45 36 [2] 31 2e [2] 76 2c [2] 31 3d [2] 7f 31 [2] 73 3b [2] 64 30 [2] 7f 7e [2] 42 }

  condition:
    any of them
}
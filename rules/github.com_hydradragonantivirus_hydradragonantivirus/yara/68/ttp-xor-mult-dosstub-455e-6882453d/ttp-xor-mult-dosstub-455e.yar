rule TTP_XOR_MULT_DOSStub_455e {
  strings:
    $key_455e = { 11 36 [2] 65 2e [2] 22 2c [2] 65 3d [2] 2b 31 [2] 27 3b [2] 30 30 [2] 2b 7e [2] 16 }

  condition:
    any of them
}
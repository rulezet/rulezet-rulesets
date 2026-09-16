rule TTP_XOR_MULT_DOSStub_215e {
  strings:
    $key_215e = { 75 36 [2] 01 2e [2] 46 2c [2] 01 3d [2] 4f 31 [2] 43 3b [2] 54 30 [2] 4f 7e [2] 72 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_245e {
  strings:
    $key_245e = { 70 36 [2] 04 2e [2] 43 2c [2] 04 3d [2] 4a 31 [2] 46 3b [2] 51 30 [2] 4a 7e [2] 77 }

  condition:
    any of them
}
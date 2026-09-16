rule TTP_XOR_MULT_DOSStub_285e {
  strings:
    $key_285e = { 7c 36 [2] 08 2e [2] 4f 2c [2] 08 3d [2] 46 31 [2] 4a 3b [2] 5d 30 [2] 46 7e [2] 7b }

  condition:
    any of them
}
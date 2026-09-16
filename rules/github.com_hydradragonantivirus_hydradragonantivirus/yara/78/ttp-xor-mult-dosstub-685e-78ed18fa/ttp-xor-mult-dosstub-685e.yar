rule TTP_XOR_MULT_DOSStub_685e {
  strings:
    $key_685e = { 3c 36 [2] 48 2e [2] 0f 2c [2] 48 3d [2] 06 31 [2] 0a 3b [2] 1d 30 [2] 06 7e [2] 3b }

  condition:
    any of them
}
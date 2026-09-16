rule TTP_XOR_MULT_DOSStub_6d5e {
  strings:
    $key_6d5e = { 39 36 [2] 4d 2e [2] 0a 2c [2] 4d 3d [2] 03 31 [2] 0f 3b [2] 18 30 [2] 03 7e [2] 3e }

  condition:
    any of them
}
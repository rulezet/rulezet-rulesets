rule TTP_XOR_MULT_DOSStub_5f5e {
  strings:
    $key_5f5e = { 0b 36 [2] 7f 2e [2] 38 2c [2] 7f 3d [2] 31 31 [2] 3d 3b [2] 2a 30 [2] 31 7e [2] 0c }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_3f5e {
  strings:
    $key_3f5e = { 6b 36 [2] 1f 2e [2] 58 2c [2] 1f 3d [2] 51 31 [2] 5d 3b [2] 4a 30 [2] 51 7e [2] 6c }

  condition:
    any of them
}
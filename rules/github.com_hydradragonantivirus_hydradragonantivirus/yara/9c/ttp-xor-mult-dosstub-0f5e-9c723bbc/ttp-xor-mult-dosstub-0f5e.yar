rule TTP_XOR_MULT_DOSStub_0f5e {
  strings:
    $key_0f5e = { 5b 36 [2] 2f 2e [2] 68 2c [2] 2f 3d [2] 61 31 [2] 6d 3b [2] 7a 30 [2] 61 7e [2] 5c }

  condition:
    any of them
}
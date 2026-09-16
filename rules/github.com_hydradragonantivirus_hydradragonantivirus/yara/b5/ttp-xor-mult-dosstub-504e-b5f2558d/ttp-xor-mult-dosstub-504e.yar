rule TTP_XOR_MULT_DOSStub_504e {
  strings:
    $key_504e = { 04 26 [2] 70 3e [2] 37 3c [2] 70 2d [2] 3e 21 [2] 32 2b [2] 25 20 [2] 3e 6e [2] 03 }

  condition:
    any of them
}
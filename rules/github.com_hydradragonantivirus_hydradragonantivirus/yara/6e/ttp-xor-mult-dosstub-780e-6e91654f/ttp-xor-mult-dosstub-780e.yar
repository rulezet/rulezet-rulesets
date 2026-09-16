rule TTP_XOR_MULT_DOSStub_780e {
  strings:
    $key_780e = { 2c 66 [2] 58 7e [2] 1f 7c [2] 58 6d [2] 16 61 [2] 1a 6b [2] 0d 60 [2] 16 2e [2] 2b }

  condition:
    any of them
}
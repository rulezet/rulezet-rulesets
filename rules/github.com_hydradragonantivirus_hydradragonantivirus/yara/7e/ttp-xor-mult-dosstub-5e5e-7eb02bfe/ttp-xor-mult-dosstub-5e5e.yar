rule TTP_XOR_MULT_DOSStub_5e5e {
  strings:
    $key_5e5e = { 0a 36 [2] 7e 2e [2] 39 2c [2] 7e 3d [2] 30 31 [2] 3c 3b [2] 2b 30 [2] 30 7e [2] 0d }

  condition:
    any of them
}
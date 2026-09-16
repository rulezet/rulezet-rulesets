rule TTP_XOR_MULT_DOSStub_7b5e {
  strings:
    $key_7b5e = { 2f 36 [2] 5b 2e [2] 1c 2c [2] 5b 3d [2] 15 31 [2] 19 3b [2] 0e 30 [2] 15 7e [2] 28 }

  condition:
    any of them
}
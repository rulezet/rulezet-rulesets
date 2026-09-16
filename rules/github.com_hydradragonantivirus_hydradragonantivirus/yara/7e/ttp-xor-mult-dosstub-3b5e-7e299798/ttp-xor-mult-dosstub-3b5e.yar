rule TTP_XOR_MULT_DOSStub_3b5e {
  strings:
    $key_3b5e = { 6f 36 [2] 1b 2e [2] 5c 2c [2] 1b 3d [2] 55 31 [2] 59 3b [2] 4e 30 [2] 55 7e [2] 68 }

  condition:
    any of them
}
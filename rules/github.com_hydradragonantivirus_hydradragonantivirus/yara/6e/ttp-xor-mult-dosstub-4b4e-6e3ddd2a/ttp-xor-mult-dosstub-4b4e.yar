rule TTP_XOR_MULT_DOSStub_4b4e {
  strings:
    $key_4b4e = { 1f 26 [2] 6b 3e [2] 2c 3c [2] 6b 2d [2] 25 21 [2] 29 2b [2] 3e 20 [2] 25 6e [2] 18 }

  condition:
    any of them
}
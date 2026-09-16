rule TTP_XOR_MULT_DOSStub_5b5e {
  strings:
    $key_5b5e = { 0f 36 [2] 7b 2e [2] 3c 2c [2] 7b 3d [2] 35 31 [2] 39 3b [2] 2e 30 [2] 35 7e [2] 08 }

  condition:
    any of them
}
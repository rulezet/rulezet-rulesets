rule TTP_XOR_MULT_DOSStub_ac4e {
  strings:
    $key_ac4e = { f8 26 [2] 8c 3e [2] cb 3c [2] 8c 2d [2] c2 21 [2] ce 2b [2] d9 20 [2] c2 6e [2] ff }

  condition:
    any of them
}
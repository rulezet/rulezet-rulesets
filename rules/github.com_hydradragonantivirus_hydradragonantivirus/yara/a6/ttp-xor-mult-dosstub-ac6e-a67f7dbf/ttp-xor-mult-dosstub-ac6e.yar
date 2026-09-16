rule TTP_XOR_MULT_DOSStub_ac6e {
  strings:
    $key_ac6e = { f8 06 [2] 8c 1e [2] cb 1c [2] 8c 0d [2] c2 01 [2] ce 0b [2] d9 00 [2] c2 4e [2] ff }

  condition:
    any of them
}
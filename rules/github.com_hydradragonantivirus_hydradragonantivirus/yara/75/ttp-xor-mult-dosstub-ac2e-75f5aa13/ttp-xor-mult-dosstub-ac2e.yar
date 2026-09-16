rule TTP_XOR_MULT_DOSStub_ac2e {
  strings:
    $key_ac2e = { f8 46 [2] 8c 5e [2] cb 5c [2] 8c 4d [2] c2 41 [2] ce 4b [2] d9 40 [2] c2 0e [2] ff }

  condition:
    any of them
}
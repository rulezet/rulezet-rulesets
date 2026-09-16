rule TTP_XOR_MULT_DOSStub_ac3e {
  strings:
    $key_ac3e = { f8 56 [2] 8c 4e [2] cb 4c [2] 8c 5d [2] c2 51 [2] ce 5b [2] d9 50 [2] c2 1e [2] ff }

  condition:
    any of them
}
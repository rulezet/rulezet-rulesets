rule TTP_XOR_MULT_DOSStub_ac6d {
  strings:
    $key_ac6d = { f8 05 [2] 8c 1d [2] cb 1f [2] 8c 0e [2] c2 02 [2] ce 08 [2] d9 03 [2] c2 4d [2] ff }

  condition:
    any of them
}
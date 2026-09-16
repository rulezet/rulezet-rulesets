rule TTP_XOR_MULT_DOSStub_ac1d {
  strings:
    $key_ac1d = { f8 75 [2] 8c 6d [2] cb 6f [2] 8c 7e [2] c2 72 [2] ce 78 [2] d9 73 [2] c2 3d [2] ff }

  condition:
    any of them
}
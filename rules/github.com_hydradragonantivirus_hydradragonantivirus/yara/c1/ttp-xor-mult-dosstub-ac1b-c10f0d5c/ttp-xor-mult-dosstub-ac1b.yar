rule TTP_XOR_MULT_DOSStub_ac1b {
  strings:
    $key_ac1b = { f8 73 [2] 8c 6b [2] cb 69 [2] 8c 78 [2] c2 74 [2] ce 7e [2] d9 75 [2] c2 3b [2] ff }

  condition:
    any of them
}
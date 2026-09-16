rule TTP_XOR_MULT_DOSStub_ac1c {
  strings:
    $key_ac1c = { f8 74 [2] 8c 6c [2] cb 6e [2] 8c 7f [2] c2 73 [2] ce 79 [2] d9 72 [2] c2 3c [2] ff }

  condition:
    any of them
}
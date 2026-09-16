rule TTP_XOR_MULT_DOSStub_ac3c {
  strings:
    $key_ac3c = { f8 54 [2] 8c 4c [2] cb 4e [2] 8c 5f [2] c2 53 [2] ce 59 [2] d9 52 [2] c2 1c [2] ff }

  condition:
    any of them
}
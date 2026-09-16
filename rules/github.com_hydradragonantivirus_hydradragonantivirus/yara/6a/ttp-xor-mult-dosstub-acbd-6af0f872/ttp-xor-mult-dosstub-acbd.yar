rule TTP_XOR_MULT_DOSStub_acbd {
  strings:
    $key_acbd = { f8 d5 [2] 8c cd [2] cb cf [2] 8c de [2] c2 d2 [2] ce d8 [2] d9 d3 [2] c2 9d [2] ff }

  condition:
    any of them
}
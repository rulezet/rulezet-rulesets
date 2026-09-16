rule TTP_XOR_MULT_DOSStub_acef {
  strings:
    $key_acef = { f8 87 [2] 8c 9f [2] cb 9d [2] 8c 8c [2] c2 80 [2] ce 8a [2] d9 81 [2] c2 cf [2] ff }

  condition:
    any of them
}
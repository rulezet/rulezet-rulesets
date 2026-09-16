rule TTP_XOR_MULT_DOSStub_acec {
  strings:
    $key_acec = { f8 84 [2] 8c 9c [2] cb 9e [2] 8c 8f [2] c2 83 [2] ce 89 [2] d9 82 [2] c2 cc [2] ff }

  condition:
    any of them
}
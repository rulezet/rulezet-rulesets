rule TTP_XOR_MULT_DOSStub_acee {
  strings:
    $key_acee = { f8 86 [2] 8c 9e [2] cb 9c [2] 8c 8d [2] c2 81 [2] ce 8b [2] d9 80 [2] c2 ce [2] ff }

  condition:
    any of them
}
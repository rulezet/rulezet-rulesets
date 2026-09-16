rule TTP_XOR_MULT_DOSStub_ac35 {
  strings:
    $key_ac35 = { f8 5d [2] 8c 45 [2] cb 47 [2] 8c 56 [2] c2 5a [2] ce 50 [2] d9 5b [2] c2 15 [2] ff }

  condition:
    any of them
}
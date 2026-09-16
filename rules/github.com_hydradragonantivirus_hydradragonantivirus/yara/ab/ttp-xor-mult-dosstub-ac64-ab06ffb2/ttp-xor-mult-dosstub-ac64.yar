rule TTP_XOR_MULT_DOSStub_ac64 {
  strings:
    $key_ac64 = { f8 0c [2] 8c 14 [2] cb 16 [2] 8c 07 [2] c2 0b [2] ce 01 [2] d9 0a [2] c2 44 [2] ff }

  condition:
    any of them
}
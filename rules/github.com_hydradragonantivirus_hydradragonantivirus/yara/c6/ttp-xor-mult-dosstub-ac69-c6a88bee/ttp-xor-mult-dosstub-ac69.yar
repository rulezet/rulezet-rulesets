rule TTP_XOR_MULT_DOSStub_ac69 {
  strings:
    $key_ac69 = { f8 01 [2] 8c 19 [2] cb 1b [2] 8c 0a [2] c2 06 [2] ce 0c [2] d9 07 [2] c2 49 [2] ff }

  condition:
    any of them
}
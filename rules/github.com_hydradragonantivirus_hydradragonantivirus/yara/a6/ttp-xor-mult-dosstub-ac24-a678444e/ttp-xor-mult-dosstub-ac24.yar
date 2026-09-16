rule TTP_XOR_MULT_DOSStub_ac24 {
  strings:
    $key_ac24 = { f8 4c [2] 8c 54 [2] cb 56 [2] 8c 47 [2] c2 4b [2] ce 41 [2] d9 4a [2] c2 04 [2] ff }

  condition:
    any of them
}
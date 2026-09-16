rule TTP_XOR_MULT_DOSStub_ac03 {
  strings:
    $key_ac03 = { f8 6b [2] 8c 73 [2] cb 71 [2] 8c 60 [2] c2 6c [2] ce 66 [2] d9 6d [2] c2 23 [2] ff }

  condition:
    any of them
}
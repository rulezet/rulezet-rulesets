rule TTP_XOR_MULT_DOSStub_eb35 {
  strings:
    $key_eb35 = { bf 5d [2] cb 45 [2] 8c 47 [2] cb 56 [2] 85 5a [2] 89 50 [2] 9e 5b [2] 85 15 [2] b8 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_eb29 {
  strings:
    $key_eb29 = { bf 41 [2] cb 59 [2] 8c 5b [2] cb 4a [2] 85 46 [2] 89 4c [2] 9e 47 [2] 85 09 [2] b8 }

  condition:
    any of them
}
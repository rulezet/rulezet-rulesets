rule TTP_XOR_MULT_DOSStub_eb3c {
  strings:
    $key_eb3c = { bf 54 [2] cb 4c [2] 8c 4e [2] cb 5f [2] 85 53 [2] 89 59 [2] 9e 52 [2] 85 1c [2] b8 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_eb1c {
  strings:
    $key_eb1c = { bf 74 [2] cb 6c [2] 8c 6e [2] cb 7f [2] 85 73 [2] 89 79 [2] 9e 72 [2] 85 3c [2] b8 }

  condition:
    any of them
}
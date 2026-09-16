rule TTP_XOR_MULT_DOSStub_ebe3 {
  strings:
    $key_ebe3 = { bf 8b [2] cb 93 [2] 8c 91 [2] cb 80 [2] 85 8c [2] 89 86 [2] 9e 8d [2] 85 c3 [2] b8 }

  condition:
    any of them
}
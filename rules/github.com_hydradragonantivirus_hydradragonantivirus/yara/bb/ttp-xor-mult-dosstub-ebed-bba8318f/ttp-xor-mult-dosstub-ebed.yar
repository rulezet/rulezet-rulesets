rule TTP_XOR_MULT_DOSStub_ebed {
  strings:
    $key_ebed = { bf 85 [2] cb 9d [2] 8c 9f [2] cb 8e [2] 85 82 [2] 89 88 [2] 9e 83 [2] 85 cd [2] b8 }

  condition:
    any of them
}
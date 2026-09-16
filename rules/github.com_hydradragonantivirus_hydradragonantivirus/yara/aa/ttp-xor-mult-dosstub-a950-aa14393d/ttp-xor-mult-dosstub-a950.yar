rule TTP_XOR_MULT_DOSStub_a950 {
  strings:
    $key_a950 = { fd 38 [2] 89 20 [2] ce 22 [2] 89 33 [2] c7 3f [2] cb 35 [2] dc 3e [2] c7 70 [2] fa }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_ac1f {
  strings:
    $key_ac1f = { f8 77 [2] 8c 6f [2] cb 6d [2] 8c 7c [2] c2 70 [2] ce 7a [2] d9 71 [2] c2 3f [2] ff }

  condition:
    any of them
}
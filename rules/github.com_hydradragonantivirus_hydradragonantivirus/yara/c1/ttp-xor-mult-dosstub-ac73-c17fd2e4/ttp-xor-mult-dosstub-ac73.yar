rule TTP_XOR_MULT_DOSStub_ac73 {
  strings:
    $key_ac73 = { f8 1b [2] 8c 03 [2] cb 01 [2] 8c 10 [2] c2 1c [2] ce 16 [2] d9 1d [2] c2 53 [2] ff }

  condition:
    any of them
}
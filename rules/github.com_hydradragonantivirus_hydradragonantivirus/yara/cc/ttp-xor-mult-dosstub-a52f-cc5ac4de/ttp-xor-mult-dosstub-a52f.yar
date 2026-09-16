rule TTP_XOR_MULT_DOSStub_a52f {
  strings:
    $key_a52f = { f1 47 [2] 85 5f [2] c2 5d [2] 85 4c [2] cb 40 [2] c7 4a [2] d0 41 [2] cb 0f [2] f6 }

  condition:
    any of them
}
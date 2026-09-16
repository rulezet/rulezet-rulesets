rule TTP_XOR_MULT_DOSStub_5b55 {
  strings:
    $key_5b55 = { 0f 3d [2] 7b 25 [2] 3c 27 [2] 7b 36 [2] 35 3a [2] 39 30 [2] 2e 3b [2] 35 75 [2] 08 }

  condition:
    any of them
}
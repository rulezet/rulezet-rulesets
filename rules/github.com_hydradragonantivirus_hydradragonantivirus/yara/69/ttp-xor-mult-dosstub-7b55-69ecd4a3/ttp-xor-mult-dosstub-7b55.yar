rule TTP_XOR_MULT_DOSStub_7b55 {
  strings:
    $key_7b55 = { 2f 3d [2] 5b 25 [2] 1c 27 [2] 5b 36 [2] 15 3a [2] 19 30 [2] 0e 3b [2] 15 75 [2] 28 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_4b55 {
  strings:
    $key_4b55 = { 1f 3d [2] 6b 25 [2] 2c 27 [2] 6b 36 [2] 25 3a [2] 29 30 [2] 3e 3b [2] 25 75 [2] 18 }

  condition:
    any of them
}
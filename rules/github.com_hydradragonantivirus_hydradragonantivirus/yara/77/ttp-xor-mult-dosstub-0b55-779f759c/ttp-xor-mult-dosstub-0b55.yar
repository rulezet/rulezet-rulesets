rule TTP_XOR_MULT_DOSStub_0b55 {
  strings:
    $key_0b55 = { 5f 3d [2] 2b 25 [2] 6c 27 [2] 2b 36 [2] 65 3a [2] 69 30 [2] 7e 3b [2] 65 75 [2] 58 }

  condition:
    any of them
}
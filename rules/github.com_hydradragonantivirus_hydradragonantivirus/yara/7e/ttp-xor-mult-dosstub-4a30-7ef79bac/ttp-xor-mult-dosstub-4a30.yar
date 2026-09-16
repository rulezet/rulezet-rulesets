rule TTP_XOR_MULT_DOSStub_4a30 {
  strings:
    $key_4a30 = { 1e 58 [2] 6a 40 [2] 2d 42 [2] 6a 53 [2] 24 5f [2] 28 55 [2] 3f 5e [2] 24 10 [2] 19 }

  condition:
    any of them
}
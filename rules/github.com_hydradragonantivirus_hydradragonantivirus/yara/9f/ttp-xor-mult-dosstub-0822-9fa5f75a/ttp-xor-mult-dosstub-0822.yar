rule TTP_XOR_MULT_DOSStub_0822 {
  strings:
    $key_0822 = { 5c 4a [2] 28 52 [2] 6f 50 [2] 28 41 [2] 66 4d [2] 6a 47 [2] 7d 4c [2] 66 02 [2] 5b }

  condition:
    any of them
}
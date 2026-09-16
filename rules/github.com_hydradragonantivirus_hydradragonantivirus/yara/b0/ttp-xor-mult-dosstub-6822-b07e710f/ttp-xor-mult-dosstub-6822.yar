rule TTP_XOR_MULT_DOSStub_6822 {
  strings:
    $key_6822 = { 3c 4a [2] 48 52 [2] 0f 50 [2] 48 41 [2] 06 4d [2] 0a 47 [2] 1d 4c [2] 06 02 [2] 3b }

  condition:
    any of them
}
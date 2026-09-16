rule TTP_XOR_MULT_DOSStub_7822 {
  strings:
    $key_7822 = { 2c 4a [2] 58 52 [2] 1f 50 [2] 58 41 [2] 16 4d [2] 1a 47 [2] 0d 4c [2] 16 02 [2] 2b }

  condition:
    any of them
}
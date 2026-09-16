rule TTP_XOR_MULT_DOSStub_0944 {
  strings:
    $key_0944 = { 5d 2c [2] 29 34 [2] 6e 36 [2] 29 27 [2] 67 2b [2] 6b 21 [2] 7c 2a [2] 67 64 [2] 5a }

  condition:
    any of them
}
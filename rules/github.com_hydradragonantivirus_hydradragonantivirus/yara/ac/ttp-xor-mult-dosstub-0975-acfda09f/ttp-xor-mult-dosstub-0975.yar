rule TTP_XOR_MULT_DOSStub_0975 {
  strings:
    $key_0975 = { 5d 1d [2] 29 05 [2] 6e 07 [2] 29 16 [2] 67 1a [2] 6b 10 [2] 7c 1b [2] 67 55 [2] 5a }

  condition:
    any of them
}
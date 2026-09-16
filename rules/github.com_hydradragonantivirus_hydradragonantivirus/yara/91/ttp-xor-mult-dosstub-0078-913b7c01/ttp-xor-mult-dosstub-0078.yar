rule TTP_XOR_MULT_DOSStub_0078 {
  strings:
    $key_0078 = { 54 10 [2] 20 08 [2] 67 0a [2] 20 1b [2] 6e 17 [2] 62 1d [2] 75 16 [2] 6e 58 [2] 53 }

  condition:
    any of them
}
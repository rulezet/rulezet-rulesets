rule TTP_XOR_MULT_DOSStub_1e48 {
  strings:
    $key_1e48 = { 4a 20 [2] 3e 38 [2] 79 3a [2] 3e 2b [2] 70 27 [2] 7c 2d [2] 6b 26 [2] 70 68 [2] 4d }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_4908 {
  strings:
    $key_4908 = { 1d 60 [2] 69 78 [2] 2e 7a [2] 69 6b [2] 27 67 [2] 2b 6d [2] 3c 66 [2] 27 28 [2] 1a }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_7914 {
  strings:
    $key_7914 = { 2d 7c [2] 59 64 [2] 1e 66 [2] 59 77 [2] 17 7b [2] 1b 71 [2] 0c 7a [2] 17 34 [2] 2a }

  condition:
    any of them
}
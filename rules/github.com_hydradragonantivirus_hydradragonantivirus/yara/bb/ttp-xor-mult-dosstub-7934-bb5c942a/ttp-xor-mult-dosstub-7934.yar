rule TTP_XOR_MULT_DOSStub_7934 {
  strings:
    $key_7934 = { 2d 5c [2] 59 44 [2] 1e 46 [2] 59 57 [2] 17 5b [2] 1b 51 [2] 0c 5a [2] 17 14 [2] 2a }

  condition:
    any of them
}
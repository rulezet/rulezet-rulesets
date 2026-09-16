rule TTP_XOR_MULT_DOSStub_7928 {
  strings:
    $key_7928 = { 2d 40 [2] 59 58 [2] 1e 5a [2] 59 4b [2] 17 47 [2] 1b 4d [2] 0c 46 [2] 17 08 [2] 2a }

  condition:
    any of them
}
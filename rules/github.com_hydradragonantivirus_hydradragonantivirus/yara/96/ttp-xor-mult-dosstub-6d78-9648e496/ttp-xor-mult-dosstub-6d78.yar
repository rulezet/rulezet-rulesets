rule TTP_XOR_MULT_DOSStub_6d78 {
  strings:
    $key_6d78 = { 39 10 [2] 4d 08 [2] 0a 0a [2] 4d 1b [2] 03 17 [2] 0f 1d [2] 18 16 [2] 03 58 [2] 3e }

  condition:
    any of them
}
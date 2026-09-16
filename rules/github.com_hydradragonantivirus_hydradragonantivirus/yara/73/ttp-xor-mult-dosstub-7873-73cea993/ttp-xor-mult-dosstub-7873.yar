rule TTP_XOR_MULT_DOSStub_7873 {
  strings:
    $key_7873 = { 2c 1b [2] 58 03 [2] 1f 01 [2] 58 10 [2] 16 1c [2] 1a 16 [2] 0d 1d [2] 16 53 [2] 2b }

  condition:
    any of them
}
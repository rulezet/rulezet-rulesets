rule TTP_XOR_MULT_DOSStub_6873 {
  strings:
    $key_6873 = { 3c 1b [2] 48 03 [2] 0f 01 [2] 48 10 [2] 06 1c [2] 0a 16 [2] 1d 1d [2] 06 53 [2] 3b }

  condition:
    any of them
}
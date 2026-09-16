rule TTP_XOR_MULT_DOSStub_6d43 {
  strings:
    $key_6d43 = { 39 2b [2] 4d 33 [2] 0a 31 [2] 4d 20 [2] 03 2c [2] 0f 26 [2] 18 2d [2] 03 63 [2] 3e }

  condition:
    any of them
}
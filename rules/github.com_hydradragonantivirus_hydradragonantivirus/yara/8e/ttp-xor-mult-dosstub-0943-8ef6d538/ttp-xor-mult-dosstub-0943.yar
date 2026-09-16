rule TTP_XOR_MULT_DOSStub_0943 {
  strings:
    $key_0943 = { 5d 2b [2] 29 33 [2] 6e 31 [2] 29 20 [2] 67 2c [2] 6b 26 [2] 7c 2d [2] 67 63 [2] 5a }

  condition:
    any of them
}
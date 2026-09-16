rule TTP_XOR_MULT_DOSStub_7943 {
  strings:
    $key_7943 = { 2d 2b [2] 59 33 [2] 1e 31 [2] 59 20 [2] 17 2c [2] 1b 26 [2] 0c 2d [2] 17 63 [2] 2a }

  condition:
    any of them
}
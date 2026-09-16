rule TTP_XOR_MULT_DOSStub_3e43 {
  strings:
    $key_3e43 = { 6a 2b [2] 1e 33 [2] 59 31 [2] 1e 20 [2] 50 2c [2] 5c 26 [2] 4b 2d [2] 50 63 [2] 6d }

  condition:
    any of them
}
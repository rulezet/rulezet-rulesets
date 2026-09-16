rule TTP_XOR_MULT_DOSStub_3943 {
  strings:
    $key_3943 = { 6d 2b [2] 19 33 [2] 5e 31 [2] 19 20 [2] 57 2c [2] 5b 26 [2] 4c 2d [2] 57 63 [2] 6a }

  condition:
    any of them
}
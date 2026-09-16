rule TTP_XOR_MULT_DOSStub_4e23 {
  strings:
    $key_4e23 = { 1a 4b [2] 6e 53 [2] 29 51 [2] 6e 40 [2] 20 4c [2] 2c 46 [2] 3b 4d [2] 20 03 [2] 1d }

  condition:
    any of them
}
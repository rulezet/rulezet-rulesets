rule TTP_XOR_MULT_DOSStub_4b05 {
  strings:
    $key_4b05 = { 1f 6d [2] 6b 75 [2] 2c 77 [2] 6b 66 [2] 25 6a [2] 29 60 [2] 3e 6b [2] 25 25 [2] 18 }

  condition:
    any of them
}
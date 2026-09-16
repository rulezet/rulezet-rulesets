rule TTP_XOR_MULT_DOSStub_0b05 {
  strings:
    $key_0b05 = { 5f 6d [2] 2b 75 [2] 6c 77 [2] 2b 66 [2] 65 6a [2] 69 60 [2] 7e 6b [2] 65 25 [2] 58 }

  condition:
    any of them
}
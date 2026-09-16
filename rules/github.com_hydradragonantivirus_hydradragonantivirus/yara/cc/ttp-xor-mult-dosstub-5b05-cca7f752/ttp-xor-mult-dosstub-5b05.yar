rule TTP_XOR_MULT_DOSStub_5b05 {
  strings:
    $key_5b05 = { 0f 6d [2] 7b 75 [2] 3c 77 [2] 7b 66 [2] 35 6a [2] 39 60 [2] 2e 6b [2] 35 25 [2] 08 }

  condition:
    any of them
}
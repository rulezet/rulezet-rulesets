rule TTP_XOR_MULT_DOSStub_3b05 {
  strings:
    $key_3b05 = { 6f 6d [2] 1b 75 [2] 5c 77 [2] 1b 66 [2] 55 6a [2] 59 60 [2] 4e 6b [2] 55 25 [2] 68 }

  condition:
    any of them
}
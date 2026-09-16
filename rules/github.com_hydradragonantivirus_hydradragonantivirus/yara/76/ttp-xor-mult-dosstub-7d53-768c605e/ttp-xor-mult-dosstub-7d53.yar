rule TTP_XOR_MULT_DOSStub_7d53 {
  strings:
    $key_7d53 = { 29 3b [2] 5d 23 [2] 1a 21 [2] 5d 30 [2] 13 3c [2] 1f 36 [2] 08 3d [2] 13 73 [2] 2e }

  condition:
    any of them
}
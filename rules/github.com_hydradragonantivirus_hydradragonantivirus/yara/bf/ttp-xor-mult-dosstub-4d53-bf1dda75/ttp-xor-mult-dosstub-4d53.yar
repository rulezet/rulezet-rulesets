rule TTP_XOR_MULT_DOSStub_4d53 {
  strings:
    $key_4d53 = { 19 3b [2] 6d 23 [2] 2a 21 [2] 6d 30 [2] 23 3c [2] 2f 36 [2] 38 3d [2] 23 73 [2] 1e }

  condition:
    any of them
}
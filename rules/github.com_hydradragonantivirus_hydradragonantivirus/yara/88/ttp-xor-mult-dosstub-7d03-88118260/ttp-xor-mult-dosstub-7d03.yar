rule TTP_XOR_MULT_DOSStub_7d03 {
  strings:
    $key_7d03 = { 29 6b [2] 5d 73 [2] 1a 71 [2] 5d 60 [2] 13 6c [2] 1f 66 [2] 08 6d [2] 13 23 [2] 2e }

  condition:
    any of them
}
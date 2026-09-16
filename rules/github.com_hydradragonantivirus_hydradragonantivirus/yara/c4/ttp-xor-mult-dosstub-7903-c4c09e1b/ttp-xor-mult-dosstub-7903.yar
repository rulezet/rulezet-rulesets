rule TTP_XOR_MULT_DOSStub_7903 {
  strings:
    $key_7903 = { 2d 6b [2] 59 73 [2] 1e 71 [2] 59 60 [2] 17 6c [2] 1b 66 [2] 0c 6d [2] 17 23 [2] 2a }

  condition:
    any of them
}
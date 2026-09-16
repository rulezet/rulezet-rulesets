rule TTP_XOR_MULT_DOSStub_3274 {
  strings:
    $key_3274 = { 66 1c [2] 12 04 [2] 55 06 [2] 12 17 [2] 5c 1b [2] 50 11 [2] 47 1a [2] 5c 54 [2] 61 }

  condition:
    any of them
}
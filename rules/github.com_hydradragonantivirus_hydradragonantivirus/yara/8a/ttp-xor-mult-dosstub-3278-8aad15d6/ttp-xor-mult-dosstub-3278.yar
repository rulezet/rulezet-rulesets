rule TTP_XOR_MULT_DOSStub_3278 {
  strings:
    $key_3278 = { 66 10 [2] 12 08 [2] 55 0a [2] 12 1b [2] 5c 17 [2] 50 1d [2] 47 16 [2] 5c 58 [2] 61 }

  condition:
    any of them
}
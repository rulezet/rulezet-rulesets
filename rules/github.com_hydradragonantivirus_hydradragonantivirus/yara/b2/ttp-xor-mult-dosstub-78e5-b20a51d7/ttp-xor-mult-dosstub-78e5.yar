rule TTP_XOR_MULT_DOSStub_78e5 {
  strings:
    $key_78e5 = { 2c 8d [2] 58 95 [2] 1f 97 [2] 58 86 [2] 16 8a [2] 1a 80 [2] 0d 8b [2] 16 c5 [2] 2b }

  condition:
    any of them
}
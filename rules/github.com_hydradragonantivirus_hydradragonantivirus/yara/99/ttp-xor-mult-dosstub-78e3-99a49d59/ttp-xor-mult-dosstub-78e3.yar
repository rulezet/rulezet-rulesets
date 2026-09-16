rule TTP_XOR_MULT_DOSStub_78e3 {
  strings:
    $key_78e3 = { 2c 8b [2] 58 93 [2] 1f 91 [2] 58 80 [2] 16 8c [2] 1a 86 [2] 0d 8d [2] 16 c3 [2] 2b }

  condition:
    any of them
}
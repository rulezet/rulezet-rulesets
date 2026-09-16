rule TTP_XOR_MULT_DOSStub_2616 {
  strings:
    $key_2616 = { 72 7e [2] 06 66 [2] 41 64 [2] 06 75 [2] 48 79 [2] 44 73 [2] 53 78 [2] 48 36 [2] 75 }

  condition:
    any of them
}
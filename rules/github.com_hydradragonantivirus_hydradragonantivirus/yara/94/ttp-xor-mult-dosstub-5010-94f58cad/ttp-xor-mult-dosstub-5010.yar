rule TTP_XOR_MULT_DOSStub_5010 {
  strings:
    $key_5010 = { 04 78 [2] 70 60 [2] 37 62 [2] 70 73 [2] 3e 7f [2] 32 75 [2] 25 7e [2] 3e 30 [2] 03 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_5d10 {
  strings:
    $key_5d10 = { 09 78 [2] 7d 60 [2] 3a 62 [2] 7d 73 [2] 33 7f [2] 3f 75 [2] 28 7e [2] 33 30 [2] 0e }

  condition:
    any of them
}
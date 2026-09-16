rule TTP_XOR_MULT_DOSStub_1310 {
  strings:
    $key_1310 = { 47 78 [2] 33 60 [2] 74 62 [2] 33 73 [2] 7d 7f [2] 71 75 [2] 66 7e [2] 7d 30 [2] 40 }

  condition:
    any of them
}
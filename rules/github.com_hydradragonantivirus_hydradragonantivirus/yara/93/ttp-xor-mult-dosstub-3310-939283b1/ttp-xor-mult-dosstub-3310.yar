rule TTP_XOR_MULT_DOSStub_3310 {
  strings:
    $key_3310 = { 67 78 [2] 13 60 [2] 54 62 [2] 13 73 [2] 5d 7f [2] 51 75 [2] 46 7e [2] 5d 30 [2] 60 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_2510 {
  strings:
    $key_2510 = { 71 78 [2] 05 60 [2] 42 62 [2] 05 73 [2] 4b 7f [2] 47 75 [2] 50 7e [2] 4b 30 [2] 76 }

  condition:
    any of them
}
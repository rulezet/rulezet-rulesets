rule TTP_XOR_MULT_DOSStub_e510 {
  strings:
    $key_e510 = { b1 78 [2] c5 60 [2] 82 62 [2] c5 73 [2] 8b 7f [2] 87 75 [2] 90 7e [2] 8b 30 [2] b6 }

  condition:
    any of them
}
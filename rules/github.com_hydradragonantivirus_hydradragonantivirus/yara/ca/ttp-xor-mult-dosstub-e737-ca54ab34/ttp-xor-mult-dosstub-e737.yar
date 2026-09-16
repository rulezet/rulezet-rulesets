rule TTP_XOR_MULT_DOSStub_e737 {
  strings:
    $key_e737 = { b3 5f [2] c7 47 [2] 80 45 [2] c7 54 [2] 89 58 [2] 85 52 [2] 92 59 [2] 89 17 [2] b4 }

  condition:
    any of them
}
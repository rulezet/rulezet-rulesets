rule TTP_XOR_MULT_DOSStub_3910 {
  strings:
    $key_3910 = { 6d 78 [2] 19 60 [2] 5e 62 [2] 19 73 [2] 57 7f [2] 5b 75 [2] 4c 7e [2] 57 30 [2] 6a }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_43eb {
  strings:
    $key_43eb = { 17 83 [2] 63 9b [2] 24 99 [2] 63 88 [2] 2d 84 [2] 21 8e [2] 36 85 [2] 2d cb [2] 10 }

  condition:
    any of them
}
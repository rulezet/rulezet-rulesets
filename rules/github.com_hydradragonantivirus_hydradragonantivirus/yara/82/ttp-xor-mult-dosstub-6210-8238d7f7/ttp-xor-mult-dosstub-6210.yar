rule TTP_XOR_MULT_DOSStub_6210 {
  strings:
    $key_6210 = { 36 78 [2] 42 60 [2] 05 62 [2] 42 73 [2] 0c 7f [2] 00 75 [2] 17 7e [2] 0c 30 [2] 31 }

  condition:
    any of them
}
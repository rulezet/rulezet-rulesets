rule TTP_XOR_MULT_DOSStub_0010 {
  strings:
    $key_0010 = { 54 78 [2] 20 60 [2] 67 62 [2] 20 73 [2] 6e 7f [2] 62 75 [2] 75 7e [2] 6e 30 [2] 53 }

  condition:
    any of them
}
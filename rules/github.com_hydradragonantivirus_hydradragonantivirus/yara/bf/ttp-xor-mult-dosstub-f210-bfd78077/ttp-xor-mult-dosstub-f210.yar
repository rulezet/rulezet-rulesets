rule TTP_XOR_MULT_DOSStub_f210 {
  strings:
    $key_f210 = { a6 78 [2] d2 60 [2] 95 62 [2] d2 73 [2] 9c 7f [2] 90 75 [2] 87 7e [2] 9c 30 [2] a1 }

  condition:
    any of them
}
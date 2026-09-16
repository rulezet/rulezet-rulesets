rule TTP_XOR_MULT_DOSStub_0131 {
  strings:
    $key_0131 = { 55 59 [2] 21 41 [2] 66 43 [2] 21 52 [2] 6f 5e [2] 63 54 [2] 74 5f [2] 6f 11 [2] 52 }

  condition:
    any of them
}
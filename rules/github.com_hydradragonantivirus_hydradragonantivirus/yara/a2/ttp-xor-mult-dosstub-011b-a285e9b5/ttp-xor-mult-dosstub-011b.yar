rule TTP_XOR_MULT_DOSStub_011b {
  strings:
    $key_011b = { 55 73 [2] 21 6b [2] 66 69 [2] 21 78 [2] 6f 74 [2] 63 7e [2] 74 75 [2] 6f 3b [2] 52 }

  condition:
    any of them
}
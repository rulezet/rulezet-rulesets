rule TTP_XOR_MULT_DOSStub_3b1b {
  strings:
    $key_3b1b = { 6f 73 [2] 1b 6b [2] 5c 69 [2] 1b 78 [2] 55 74 [2] 59 7e [2] 4e 75 [2] 55 3b [2] 68 }

  condition:
    any of them
}
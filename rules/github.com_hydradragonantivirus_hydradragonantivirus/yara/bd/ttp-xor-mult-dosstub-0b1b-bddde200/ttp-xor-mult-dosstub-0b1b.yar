rule TTP_XOR_MULT_DOSStub_0b1b {
  strings:
    $key_0b1b = { 5f 73 [2] 2b 6b [2] 6c 69 [2] 2b 78 [2] 65 74 [2] 69 7e [2] 7e 75 [2] 65 3b [2] 58 }

  condition:
    any of them
}
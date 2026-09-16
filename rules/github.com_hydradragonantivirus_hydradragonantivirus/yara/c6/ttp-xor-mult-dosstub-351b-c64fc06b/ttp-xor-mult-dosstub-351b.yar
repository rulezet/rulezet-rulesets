rule TTP_XOR_MULT_DOSStub_351b {
  strings:
    $key_351b = { 61 73 [2] 15 6b [2] 52 69 [2] 15 78 [2] 5b 74 [2] 57 7e [2] 40 75 [2] 5b 3b [2] 66 }

  condition:
    any of them
}
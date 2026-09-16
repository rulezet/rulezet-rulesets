rule TTP_XOR_MULT_DOSStub_211b {
  strings:
    $key_211b = { 75 73 [2] 01 6b [2] 46 69 [2] 01 78 [2] 4f 74 [2] 43 7e [2] 54 75 [2] 4f 3b [2] 72 }

  condition:
    any of them
}
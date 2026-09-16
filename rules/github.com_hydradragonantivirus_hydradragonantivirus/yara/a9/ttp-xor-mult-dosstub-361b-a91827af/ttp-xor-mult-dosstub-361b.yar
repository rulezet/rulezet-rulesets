rule TTP_XOR_MULT_DOSStub_361b {
  strings:
    $key_361b = { 62 73 [2] 16 6b [2] 51 69 [2] 16 78 [2] 58 74 [2] 54 7e [2] 43 75 [2] 58 3b [2] 65 }

  condition:
    any of them
}
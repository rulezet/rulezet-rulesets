rule TTP_XOR_MULT_DOSStub_565b {
  strings:
    $key_565b = { 02 33 [2] 76 2b [2] 31 29 [2] 76 38 [2] 38 34 [2] 34 3e [2] 23 35 [2] 38 7b [2] 05 }

  condition:
    any of them
}
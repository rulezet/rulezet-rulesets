rule TTP_XOR_MULT_DOSStub_5f5b {
  strings:
    $key_5f5b = { 0b 33 [2] 7f 2b [2] 38 29 [2] 7f 38 [2] 31 34 [2] 3d 3e [2] 2a 35 [2] 31 7b [2] 0c }

  condition:
    any of them
}
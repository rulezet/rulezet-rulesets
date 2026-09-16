rule TTP_XOR_MULT_DOSStub_5f2b {
  strings:
    $key_5f2b = { 0b 43 [2] 7f 5b [2] 38 59 [2] 7f 48 [2] 31 44 [2] 3d 4e [2] 2a 45 [2] 31 0b [2] 0c }

  condition:
    any of them
}
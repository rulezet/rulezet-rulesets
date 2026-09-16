rule TTP_XOR_MULT_DOSStub_7fe8 {
  strings:
    $key_7fe8 = { 2b 80 [2] 5f 98 [2] 18 9a [2] 5f 8b [2] 11 87 [2] 1d 8d [2] 0a 86 [2] 11 c8 [2] 2c }

  condition:
    any of them
}
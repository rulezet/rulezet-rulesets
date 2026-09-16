rule TTP_XOR_MULT_DOSStub_7f71 {
  strings:
    $key_7f71 = { 2b 19 [2] 5f 01 [2] 18 03 [2] 5f 12 [2] 11 1e [2] 1d 14 [2] 0a 1f [2] 11 51 [2] 2c }

  condition:
    any of them
}
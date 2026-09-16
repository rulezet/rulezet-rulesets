rule TTP_XOR_MULT_DOSStub_7f0c {
  strings:
    $key_7f0c = { 2b 64 [2] 5f 7c [2] 18 7e [2] 5f 6f [2] 11 63 [2] 1d 69 [2] 0a 62 [2] 11 2c [2] 2c }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_4f0c {
  strings:
    $key_4f0c = { 1b 64 [2] 6f 7c [2] 28 7e [2] 6f 6f [2] 21 63 [2] 2d 69 [2] 3a 62 [2] 21 2c [2] 1c }

  condition:
    any of them
}
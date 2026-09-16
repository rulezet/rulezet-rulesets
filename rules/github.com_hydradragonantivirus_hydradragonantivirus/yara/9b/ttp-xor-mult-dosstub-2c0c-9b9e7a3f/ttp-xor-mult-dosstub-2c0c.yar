rule TTP_XOR_MULT_DOSStub_2c0c {
  strings:
    $key_2c0c = { 78 64 [2] 0c 7c [2] 4b 7e [2] 0c 6f [2] 42 63 [2] 4e 69 [2] 59 62 [2] 42 2c [2] 7f }

  condition:
    any of them
}
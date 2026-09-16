rule TTP_XOR_MULT_DOSStub_4e0c {
  strings:
    $key_4e0c = { 1a 64 [2] 6e 7c [2] 29 7e [2] 6e 6f [2] 20 63 [2] 2c 69 [2] 3b 62 [2] 20 2c [2] 1d }

  condition:
    any of them
}
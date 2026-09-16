rule TTP_XOR_MULT_DOSStub_7c0c {
  strings:
    $key_7c0c = { 28 64 [2] 5c 7c [2] 1b 7e [2] 5c 6f [2] 12 63 [2] 1e 69 [2] 09 62 [2] 12 2c [2] 2f }

  condition:
    any of them
}
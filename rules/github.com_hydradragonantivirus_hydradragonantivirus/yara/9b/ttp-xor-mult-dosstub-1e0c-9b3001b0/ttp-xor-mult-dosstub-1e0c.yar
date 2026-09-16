rule TTP_XOR_MULT_DOSStub_1e0c {
  strings:
    $key_1e0c = { 4a 64 [2] 3e 7c [2] 79 7e [2] 3e 6f [2] 70 63 [2] 7c 69 [2] 6b 62 [2] 70 2c [2] 4d }

  condition:
    any of them
}
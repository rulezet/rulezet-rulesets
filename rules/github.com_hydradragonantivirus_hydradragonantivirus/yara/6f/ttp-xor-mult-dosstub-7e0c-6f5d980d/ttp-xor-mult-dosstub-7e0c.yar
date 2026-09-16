rule TTP_XOR_MULT_DOSStub_7e0c {
  strings:
    $key_7e0c = { 2a 64 [2] 5e 7c [2] 19 7e [2] 5e 6f [2] 10 63 [2] 1c 69 [2] 0b 62 [2] 10 2c [2] 2d }

  condition:
    any of them
}
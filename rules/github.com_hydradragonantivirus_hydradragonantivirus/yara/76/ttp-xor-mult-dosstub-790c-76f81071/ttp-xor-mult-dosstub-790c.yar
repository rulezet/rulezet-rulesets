rule TTP_XOR_MULT_DOSStub_790c {
  strings:
    $key_790c = { 2d 64 [2] 59 7c [2] 1e 7e [2] 59 6f [2] 17 63 [2] 1b 69 [2] 0c 62 [2] 17 2c [2] 2a }

  condition:
    any of them
}
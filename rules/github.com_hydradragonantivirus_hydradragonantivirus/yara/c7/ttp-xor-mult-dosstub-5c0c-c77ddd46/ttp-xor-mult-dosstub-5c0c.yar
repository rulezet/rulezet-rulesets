rule TTP_XOR_MULT_DOSStub_5c0c {
  strings:
    $key_5c0c = { 08 64 [2] 7c 7c [2] 3b 7e [2] 7c 6f [2] 32 63 [2] 3e 69 [2] 29 62 [2] 32 2c [2] 0f }

  condition:
    any of them
}
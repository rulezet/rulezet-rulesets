rule TTP_XOR_MULT_DOSStub_3c0c {
  strings:
    $key_3c0c = { 68 64 [2] 1c 7c [2] 5b 7e [2] 1c 6f [2] 52 63 [2] 5e 69 [2] 49 62 [2] 52 2c [2] 6f }

  condition:
    any of them
}
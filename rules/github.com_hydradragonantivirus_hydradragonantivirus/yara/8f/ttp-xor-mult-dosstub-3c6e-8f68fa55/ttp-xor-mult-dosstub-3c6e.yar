rule TTP_XOR_MULT_DOSStub_3c6e {
  strings:
    $key_3c6e = { 68 06 [2] 1c 1e [2] 5b 1c [2] 1c 0d [2] 52 01 [2] 5e 0b [2] 49 00 [2] 52 4e [2] 6f }

  condition:
    any of them
}
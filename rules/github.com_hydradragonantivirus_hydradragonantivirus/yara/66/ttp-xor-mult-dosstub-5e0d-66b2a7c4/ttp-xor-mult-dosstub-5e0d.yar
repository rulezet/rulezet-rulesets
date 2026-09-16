rule TTP_XOR_MULT_DOSStub_5e0d {
  strings:
    $key_5e0d = { 0a 65 [2] 7e 7d [2] 39 7f [2] 7e 6e [2] 30 62 [2] 3c 68 [2] 2b 63 [2] 30 2d [2] 0d }

  condition:
    any of them
}
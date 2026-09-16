rule TTP_XOR_MULT_DOSStub_250d {
  strings:
    $key_250d = { 71 65 [2] 05 7d [2] 42 7f [2] 05 6e [2] 4b 62 [2] 47 68 [2] 50 63 [2] 4b 2d [2] 76 }

  condition:
    any of them
}
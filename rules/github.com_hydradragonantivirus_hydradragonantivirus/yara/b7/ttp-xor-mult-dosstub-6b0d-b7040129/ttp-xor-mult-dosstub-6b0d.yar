rule TTP_XOR_MULT_DOSStub_6b0d {
  strings:
    $key_6b0d = { 3f 65 [2] 4b 7d [2] 0c 7f [2] 4b 6e [2] 05 62 [2] 09 68 [2] 1e 63 [2] 05 2d [2] 38 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_080c {
  strings:
    $key_080c = { 5c 64 [2] 28 7c [2] 6f 7e [2] 28 6f [2] 66 63 [2] 6a 69 [2] 7d 62 [2] 66 2c [2] 5b }

  condition:
    any of them
}
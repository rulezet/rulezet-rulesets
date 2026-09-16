rule TTP_XOR_MULT_DOSStub_5a0c {
  strings:
    $key_5a0c = { 0e 64 [2] 7a 7c [2] 3d 7e [2] 7a 6f [2] 34 63 [2] 38 69 [2] 2f 62 [2] 34 2c [2] 09 }

  condition:
    any of them
}
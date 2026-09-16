rule TTP_XOR_MULT_DOSStub_130c {
  strings:
    $key_130c = { 47 64 [2] 33 7c [2] 74 7e [2] 33 6f [2] 7d 63 [2] 71 69 [2] 66 62 [2] 7d 2c [2] 40 }

  condition:
    any of them
}
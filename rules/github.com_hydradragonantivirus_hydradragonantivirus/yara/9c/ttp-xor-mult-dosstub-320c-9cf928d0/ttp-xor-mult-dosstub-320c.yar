rule TTP_XOR_MULT_DOSStub_320c {
  strings:
    $key_320c = { 66 64 [2] 12 7c [2] 55 7e [2] 12 6f [2] 5c 63 [2] 50 69 [2] 47 62 [2] 5c 2c [2] 61 }

  condition:
    any of them
}
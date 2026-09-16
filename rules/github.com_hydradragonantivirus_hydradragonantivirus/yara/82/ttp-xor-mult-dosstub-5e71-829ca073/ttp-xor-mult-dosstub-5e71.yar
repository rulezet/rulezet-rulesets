rule TTP_XOR_MULT_DOSStub_5e71 {
  strings:
    $key_5e71 = { 0a 19 [2] 7e 01 [2] 39 03 [2] 7e 12 [2] 30 1e [2] 3c 14 [2] 2b 1f [2] 30 51 [2] 0d }

  condition:
    any of them
}
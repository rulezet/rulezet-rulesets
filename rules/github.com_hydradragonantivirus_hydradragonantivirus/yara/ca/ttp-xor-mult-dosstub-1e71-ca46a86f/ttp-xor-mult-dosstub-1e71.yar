rule TTP_XOR_MULT_DOSStub_1e71 {
  strings:
    $key_1e71 = { 4a 19 [2] 3e 01 [2] 79 03 [2] 3e 12 [2] 70 1e [2] 7c 14 [2] 6b 1f [2] 70 51 [2] 4d }

  condition:
    any of them
}
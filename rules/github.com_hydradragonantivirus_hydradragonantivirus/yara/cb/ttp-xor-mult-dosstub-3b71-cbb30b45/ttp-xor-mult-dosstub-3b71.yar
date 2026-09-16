rule TTP_XOR_MULT_DOSStub_3b71 {
  strings:
    $key_3b71 = { 6f 19 [2] 1b 01 [2] 5c 03 [2] 1b 12 [2] 55 1e [2] 59 14 [2] 4e 1f [2] 55 51 [2] 68 }

  condition:
    any of them
}
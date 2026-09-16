rule TTP_XOR_MULT_DOSStub_7d0c {
  strings:
    $key_7d0c = { 29 64 [2] 5d 7c [2] 1a 7e [2] 5d 6f [2] 13 63 [2] 1f 69 [2] 08 62 [2] 13 2c [2] 2e }

  condition:
    any of them
}
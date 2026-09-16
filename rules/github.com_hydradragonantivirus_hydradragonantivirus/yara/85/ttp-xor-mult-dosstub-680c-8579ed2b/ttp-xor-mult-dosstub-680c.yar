rule TTP_XOR_MULT_DOSStub_680c {
  strings:
    $key_680c = { 3c 64 [2] 48 7c [2] 0f 7e [2] 48 6f [2] 06 63 [2] 0a 69 [2] 1d 62 [2] 06 2c [2] 3b }

  condition:
    any of them
}
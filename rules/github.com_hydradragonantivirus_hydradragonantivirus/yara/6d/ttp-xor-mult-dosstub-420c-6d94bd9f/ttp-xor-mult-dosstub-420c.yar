rule TTP_XOR_MULT_DOSStub_420c {
  strings:
    $key_420c = { 16 64 [2] 62 7c [2] 25 7e [2] 62 6f [2] 2c 63 [2] 20 69 [2] 37 62 [2] 2c 2c [2] 11 }

  condition:
    any of them
}
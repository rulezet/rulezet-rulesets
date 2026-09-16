rule TTP_XOR_MULT_DOSStub_110c {
  strings:
    $key_110c = { 45 64 [2] 31 7c [2] 76 7e [2] 31 6f [2] 7f 63 [2] 73 69 [2] 64 62 [2] 7f 2c [2] 42 }

  condition:
    any of them
}
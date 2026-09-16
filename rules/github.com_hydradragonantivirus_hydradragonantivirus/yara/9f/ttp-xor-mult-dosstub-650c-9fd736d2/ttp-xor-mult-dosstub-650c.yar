rule TTP_XOR_MULT_DOSStub_650c {
  strings:
    $key_650c = { 31 64 [2] 45 7c [2] 02 7e [2] 45 6f [2] 0b 63 [2] 07 69 [2] 10 62 [2] 0b 2c [2] 36 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_551c {
  strings:
    $key_551c = { 01 74 [2] 75 6c [2] 32 6e [2] 75 7f [2] 3b 73 [2] 37 79 [2] 20 72 [2] 3b 3c [2] 06 }

  condition:
    any of them
}
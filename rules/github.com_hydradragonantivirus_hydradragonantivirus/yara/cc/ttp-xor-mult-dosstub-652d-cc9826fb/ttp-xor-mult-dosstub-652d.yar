rule TTP_XOR_MULT_DOSStub_652d {
  strings:
    $key_652d = { 31 45 [2] 45 5d [2] 02 5f [2] 45 4e [2] 0b 42 [2] 07 48 [2] 10 43 [2] 0b 0d [2] 36 }

  condition:
    any of them
}
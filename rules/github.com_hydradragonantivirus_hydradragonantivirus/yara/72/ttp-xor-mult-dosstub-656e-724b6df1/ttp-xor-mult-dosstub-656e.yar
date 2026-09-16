rule TTP_XOR_MULT_DOSStub_656e {
  strings:
    $key_656e = { 31 06 [2] 45 1e [2] 02 1c [2] 45 0d [2] 0b 01 [2] 07 0b [2] 10 00 [2] 0b 4e [2] 36 }

  condition:
    any of them
}
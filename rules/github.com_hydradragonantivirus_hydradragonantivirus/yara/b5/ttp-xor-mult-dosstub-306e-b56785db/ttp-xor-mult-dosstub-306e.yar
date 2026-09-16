rule TTP_XOR_MULT_DOSStub_306e {
  strings:
    $key_306e = { 64 06 [2] 10 1e [2] 57 1c [2] 10 0d [2] 5e 01 [2] 52 0b [2] 45 00 [2] 5e 4e [2] 63 }

  condition:
    any of them
}
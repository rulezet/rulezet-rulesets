rule TTP_XOR_MULT_DOSStub_067e {
  strings:
    $key_067e = { 52 16 [2] 26 0e [2] 61 0c [2] 26 1d [2] 68 11 [2] 64 1b [2] 73 10 [2] 68 5e [2] 55 }

  condition:
    any of them
}
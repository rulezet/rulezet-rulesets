rule TTP_XOR_MULT_DOSStub_276e {
  strings:
    $key_276e = { 73 06 [2] 07 1e [2] 40 1c [2] 07 0d [2] 49 01 [2] 45 0b [2] 52 00 [2] 49 4e [2] 74 }

  condition:
    any of them
}
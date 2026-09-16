rule TTP_XOR_MULT_DOSStub_316e {
  strings:
    $key_316e = { 65 06 [2] 11 1e [2] 56 1c [2] 11 0d [2] 5f 01 [2] 53 0b [2] 44 00 [2] 5f 4e [2] 62 }

  condition:
    any of them
}
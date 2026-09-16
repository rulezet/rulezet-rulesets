rule TTP_XOR_MULT_DOSStub_096e {
  strings:
    $key_096e = { 5d 06 [2] 29 1e [2] 6e 1c [2] 29 0d [2] 67 01 [2] 6b 0b [2] 7c 00 [2] 67 4e [2] 5a }

  condition:
    any of them
}
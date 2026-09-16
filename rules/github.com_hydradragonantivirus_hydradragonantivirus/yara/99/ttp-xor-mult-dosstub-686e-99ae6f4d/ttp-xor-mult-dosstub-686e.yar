rule TTP_XOR_MULT_DOSStub_686e {
  strings:
    $key_686e = { 3c 06 [2] 48 1e [2] 0f 1c [2] 48 0d [2] 06 01 [2] 0a 0b [2] 1d 00 [2] 06 4e [2] 3b }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_6d6e {
  strings:
    $key_6d6e = { 39 06 [2] 4d 1e [2] 0a 1c [2] 4d 0d [2] 03 01 [2] 0f 0b [2] 18 00 [2] 03 4e [2] 3e }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_1f6e {
  strings:
    $key_1f6e = { 4b 06 [2] 3f 1e [2] 78 1c [2] 3f 0d [2] 71 01 [2] 7d 0b [2] 6a 00 [2] 71 4e [2] 4c }

  condition:
    any of them
}
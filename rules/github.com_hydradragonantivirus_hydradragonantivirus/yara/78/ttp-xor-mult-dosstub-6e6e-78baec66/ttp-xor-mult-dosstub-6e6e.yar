rule TTP_XOR_MULT_DOSStub_6e6e {
  strings:
    $key_6e6e = { 3a 06 [2] 4e 1e [2] 09 1c [2] 4e 0d [2] 00 01 [2] 0c 0b [2] 1b 00 [2] 00 4e [2] 3d }

  condition:
    any of them
}
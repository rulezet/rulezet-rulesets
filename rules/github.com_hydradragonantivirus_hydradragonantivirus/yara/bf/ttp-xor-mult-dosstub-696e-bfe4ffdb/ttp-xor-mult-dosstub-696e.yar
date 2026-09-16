rule TTP_XOR_MULT_DOSStub_696e {
  strings:
    $key_696e = { 3d 06 [2] 49 1e [2] 0e 1c [2] 49 0d [2] 07 01 [2] 0b 0b [2] 1c 00 [2] 07 4e [2] 3a }

  condition:
    any of them
}
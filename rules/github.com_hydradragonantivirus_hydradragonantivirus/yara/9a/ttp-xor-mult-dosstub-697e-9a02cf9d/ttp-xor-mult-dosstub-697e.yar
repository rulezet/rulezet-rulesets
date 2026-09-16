rule TTP_XOR_MULT_DOSStub_697e {
  strings:
    $key_697e = { 3d 16 [2] 49 0e [2] 0e 0c [2] 49 1d [2] 07 11 [2] 0b 1b [2] 1c 10 [2] 07 5e [2] 3a }

  condition:
    any of them
}
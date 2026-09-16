rule TTP_XOR_MULT_DOSStub_496e {
  strings:
    $key_496e = { 1d 06 [2] 69 1e [2] 2e 1c [2] 69 0d [2] 27 01 [2] 2b 0b [2] 3c 00 [2] 27 4e [2] 1a }

  condition:
    any of them
}
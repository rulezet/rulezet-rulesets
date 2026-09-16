rule TTP_XOR_MULT_DOSStub_591d {
  strings:
    $key_591d = { 0d 75 [2] 79 6d [2] 3e 6f [2] 79 7e [2] 37 72 [2] 3b 78 [2] 2c 73 [2] 37 3d [2] 0a }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_796d {
  strings:
    $key_796d = { 2d 05 [2] 59 1d [2] 1e 1f [2] 59 0e [2] 17 02 [2] 1b 08 [2] 0c 03 [2] 17 4d [2] 2a }

  condition:
    any of them
}
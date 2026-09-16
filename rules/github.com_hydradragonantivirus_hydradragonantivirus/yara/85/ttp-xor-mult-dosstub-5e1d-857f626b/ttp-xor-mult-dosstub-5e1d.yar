rule TTP_XOR_MULT_DOSStub_5e1d {
  strings:
    $key_5e1d = { 0a 75 [2] 7e 6d [2] 39 6f [2] 7e 7e [2] 30 72 [2] 3c 78 [2] 2b 73 [2] 30 3d [2] 0d }

  condition:
    any of them
}
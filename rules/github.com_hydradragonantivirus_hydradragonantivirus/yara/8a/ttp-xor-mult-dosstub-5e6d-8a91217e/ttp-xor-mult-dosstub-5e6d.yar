rule TTP_XOR_MULT_DOSStub_5e6d {
  strings:
    $key_5e6d = { 0a 05 [2] 7e 1d [2] 39 1f [2] 7e 0e [2] 30 02 [2] 3c 08 [2] 2b 03 [2] 30 4d [2] 0d }

  condition:
    any of them
}
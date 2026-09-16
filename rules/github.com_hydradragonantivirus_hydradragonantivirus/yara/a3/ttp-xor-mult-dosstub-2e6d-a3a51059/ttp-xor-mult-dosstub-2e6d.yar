rule TTP_XOR_MULT_DOSStub_2e6d {
  strings:
    $key_2e6d = { 7a 05 [2] 0e 1d [2] 49 1f [2] 0e 0e [2] 40 02 [2] 4c 08 [2] 5b 03 [2] 40 4d [2] 7d }

  condition:
    any of them
}
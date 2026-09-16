rule TTP_XOR_MULT_DOSStub_7e5d {
  strings:
    $key_7e5d = { 2a 35 [2] 5e 2d [2] 19 2f [2] 5e 3e [2] 10 32 [2] 1c 38 [2] 0b 33 [2] 10 7d [2] 2d }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_665d {
  strings:
    $key_665d = { 32 35 [2] 46 2d [2] 01 2f [2] 46 3e [2] 08 32 [2] 04 38 [2] 13 33 [2] 08 7d [2] 35 }

  condition:
    any of them
}
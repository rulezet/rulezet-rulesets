rule TTP_XOR_MULT_DOSStub_255d {
  strings:
    $key_255d = { 71 35 [2] 05 2d [2] 42 2f [2] 05 3e [2] 4b 32 [2] 47 38 [2] 50 33 [2] 4b 7d [2] 76 }

  condition:
    any of them
}
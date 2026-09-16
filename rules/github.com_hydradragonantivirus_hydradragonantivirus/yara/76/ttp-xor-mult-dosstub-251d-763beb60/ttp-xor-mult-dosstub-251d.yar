rule TTP_XOR_MULT_DOSStub_251d {
  strings:
    $key_251d = { 71 75 [2] 05 6d [2] 42 6f [2] 05 7e [2] 4b 72 [2] 47 78 [2] 50 73 [2] 4b 3d [2] 76 }

  condition:
    any of them
}
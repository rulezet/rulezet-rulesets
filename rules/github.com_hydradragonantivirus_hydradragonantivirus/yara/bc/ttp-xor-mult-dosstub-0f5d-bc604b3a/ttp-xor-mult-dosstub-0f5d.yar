rule TTP_XOR_MULT_DOSStub_0f5d {
  strings:
    $key_0f5d = { 5b 35 [2] 2f 2d [2] 68 2f [2] 2f 3e [2] 61 32 [2] 6d 38 [2] 7a 33 [2] 61 7d [2] 5c }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_667d {
  strings:
    $key_667d = { 32 15 [2] 46 0d [2] 01 0f [2] 46 1e [2] 08 12 [2] 04 18 [2] 13 13 [2] 08 5d [2] 35 }

  condition:
    any of them
}
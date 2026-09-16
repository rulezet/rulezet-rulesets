rule TTP_XOR_MULT_DOSStub_6efc {
  strings:
    $key_6efc = { 3a 94 [2] 4e 8c [2] 09 8e [2] 4e 9f [2] 00 93 [2] 0c 99 [2] 1b 92 [2] 00 dc [2] 3d }

  condition:
    any of them
}
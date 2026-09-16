rule TTP_XOR_MULT_DOSStub_3cfc {
  strings:
    $key_3cfc = { 68 94 [2] 1c 8c [2] 5b 8e [2] 1c 9f [2] 52 93 [2] 5e 99 [2] 49 92 [2] 52 dc [2] 6f }

  condition:
    any of them
}
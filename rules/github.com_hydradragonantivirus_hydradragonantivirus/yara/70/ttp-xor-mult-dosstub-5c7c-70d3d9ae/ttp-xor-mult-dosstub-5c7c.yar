rule TTP_XOR_MULT_DOSStub_5c7c {
  strings:
    $key_5c7c = { 08 14 [2] 7c 0c [2] 3b 0e [2] 7c 1f [2] 32 13 [2] 3e 19 [2] 29 12 [2] 32 5c [2] 0f }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_5c2c {
  strings:
    $key_5c2c = { 08 44 [2] 7c 5c [2] 3b 5e [2] 7c 4f [2] 32 43 [2] 3e 49 [2] 29 42 [2] 32 0c [2] 0f }

  condition:
    any of them
}
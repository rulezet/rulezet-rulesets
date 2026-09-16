rule TTP_XOR_MULT_DOSStub_5c27 {
  strings:
    $key_5c27 = { 08 4f [2] 7c 57 [2] 3b 55 [2] 7c 44 [2] 32 48 [2] 3e 42 [2] 29 49 [2] 32 07 [2] 0f }

  condition:
    any of them
}
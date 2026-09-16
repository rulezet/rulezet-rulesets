rule TTP_XOR_MULT_DOSStub_5c1c {
  strings:
    $key_5c1c = { 08 74 [2] 7c 6c [2] 3b 6e [2] 7c 7f [2] 32 73 [2] 3e 79 [2] 29 72 [2] 32 3c [2] 0f }

  condition:
    any of them
}
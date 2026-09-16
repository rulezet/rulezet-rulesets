rule TTP_XOR_MULT_DOSStub_1beb {
  strings:
    $key_1beb = { 4f 83 [2] 3b 9b [2] 7c 99 [2] 3b 88 [2] 75 84 [2] 79 8e [2] 6e 85 [2] 75 cb [2] 48 }

  condition:
    any of them
}
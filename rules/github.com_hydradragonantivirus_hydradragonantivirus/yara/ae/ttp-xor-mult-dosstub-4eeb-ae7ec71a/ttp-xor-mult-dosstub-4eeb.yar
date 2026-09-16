rule TTP_XOR_MULT_DOSStub_4eeb {
  strings:
    $key_4eeb = { 1a 83 [2] 6e 9b [2] 29 99 [2] 6e 88 [2] 20 84 [2] 2c 8e [2] 3b 85 [2] 20 cb [2] 1d }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_7eeb {
  strings:
    $key_7eeb = { 2a 83 [2] 5e 9b [2] 19 99 [2] 5e 88 [2] 10 84 [2] 1c 8e [2] 0b 85 [2] 10 cb [2] 2d }

  condition:
    any of them
}
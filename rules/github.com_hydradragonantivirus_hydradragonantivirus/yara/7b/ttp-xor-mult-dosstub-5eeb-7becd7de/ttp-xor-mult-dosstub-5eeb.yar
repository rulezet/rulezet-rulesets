rule TTP_XOR_MULT_DOSStub_5eeb {
  strings:
    $key_5eeb = { 0a 83 [2] 7e 9b [2] 39 99 [2] 7e 88 [2] 30 84 [2] 3c 8e [2] 2b 85 [2] 30 cb [2] 0d }

  condition:
    any of them
}
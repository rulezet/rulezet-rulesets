rule TTP_XOR_MULT_DOSStub_6eeb {
  strings:
    $key_6eeb = { 3a 83 [2] 4e 9b [2] 09 99 [2] 4e 88 [2] 00 84 [2] 0c 8e [2] 1b 85 [2] 00 cb [2] 3d }

  condition:
    any of them
}
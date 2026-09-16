rule TTP_XOR_MULT_DOSStub_78eb {
  strings:
    $key_78eb = { 2c 83 [2] 58 9b [2] 1f 99 [2] 58 88 [2] 16 84 [2] 1a 8e [2] 0d 85 [2] 16 cb [2] 2b }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_58eb {
  strings:
    $key_58eb = { 0c 83 [2] 78 9b [2] 3f 99 [2] 78 88 [2] 36 84 [2] 3a 8e [2] 2d 85 [2] 36 cb [2] 0b }

  condition:
    any of them
}
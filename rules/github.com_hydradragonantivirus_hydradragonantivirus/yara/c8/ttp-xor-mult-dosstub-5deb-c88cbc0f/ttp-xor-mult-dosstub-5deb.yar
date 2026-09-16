rule TTP_XOR_MULT_DOSStub_5deb {
  strings:
    $key_5deb = { 09 83 [2] 7d 9b [2] 3a 99 [2] 7d 88 [2] 33 84 [2] 3f 8e [2] 28 85 [2] 33 cb [2] 0e }

  condition:
    any of them
}
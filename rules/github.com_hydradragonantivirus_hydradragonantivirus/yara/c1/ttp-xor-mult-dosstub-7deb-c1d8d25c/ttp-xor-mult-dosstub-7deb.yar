rule TTP_XOR_MULT_DOSStub_7deb {
  strings:
    $key_7deb = { 29 83 [2] 5d 9b [2] 1a 99 [2] 5d 88 [2] 13 84 [2] 1f 8e [2] 08 85 [2] 13 cb [2] 2e }

  condition:
    any of them
}
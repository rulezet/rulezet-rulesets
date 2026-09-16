rule TTP_XOR_MULT_DOSStub_79eb {
  strings:
    $key_79eb = { 2d 83 [2] 59 9b [2] 1e 99 [2] 59 88 [2] 17 84 [2] 1b 8e [2] 0c 85 [2] 17 cb [2] 2a }

  condition:
    any of them
}
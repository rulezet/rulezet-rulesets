rule TTP_XOR_MULT_DOSStub_25eb {
  strings:
    $key_25eb = { 71 83 [2] 05 9b [2] 42 99 [2] 05 88 [2] 4b 84 [2] 47 8e [2] 50 85 [2] 4b cb [2] 76 }

  condition:
    any of them
}
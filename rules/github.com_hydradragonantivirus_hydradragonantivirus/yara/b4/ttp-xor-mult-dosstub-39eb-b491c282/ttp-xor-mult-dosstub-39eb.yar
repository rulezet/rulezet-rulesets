rule TTP_XOR_MULT_DOSStub_39eb {
  strings:
    $key_39eb = { 6d 83 [2] 19 9b [2] 5e 99 [2] 19 88 [2] 57 84 [2] 5b 8e [2] 4c 85 [2] 57 cb [2] 6a }

  condition:
    any of them
}
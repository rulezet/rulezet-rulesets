rule TTP_XOR_MULT_DOSStub_32eb {
  strings:
    $key_32eb = { 66 83 [2] 12 9b [2] 55 99 [2] 12 88 [2] 5c 84 [2] 50 8e [2] 47 85 [2] 5c cb [2] 61 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_24eb {
  strings:
    $key_24eb = { 70 83 [2] 04 9b [2] 43 99 [2] 04 88 [2] 4a 84 [2] 46 8e [2] 51 85 [2] 4a cb [2] 77 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_73ed {
  strings:
    $key_73ed = { 27 85 [2] 53 9d [2] 14 9f [2] 53 8e [2] 1d 82 [2] 11 88 [2] 06 83 [2] 1d cd [2] 20 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_336c {
  strings:
    $key_336c = { 67 04 [2] 13 1c [2] 54 1e [2] 13 0f [2] 5d 03 [2] 51 09 [2] 46 02 [2] 5d 4c [2] 60 }

  condition:
    any of them
}
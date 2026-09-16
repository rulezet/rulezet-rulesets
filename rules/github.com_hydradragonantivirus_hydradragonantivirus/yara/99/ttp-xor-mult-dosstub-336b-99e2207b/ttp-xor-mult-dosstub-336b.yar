rule TTP_XOR_MULT_DOSStub_336b {
  strings:
    $key_336b = { 67 03 [2] 13 1b [2] 54 19 [2] 13 08 [2] 5d 04 [2] 51 0e [2] 46 05 [2] 5d 4b [2] 60 }

  condition:
    any of them
}
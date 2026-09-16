rule TTP_XOR_MULT_DOSStub_732b {
  strings:
    $key_732b = { 27 43 [2] 53 5b [2] 14 59 [2] 53 48 [2] 1d 44 [2] 11 4e [2] 06 45 [2] 1d 0b [2] 20 }

  condition:
    any of them
}
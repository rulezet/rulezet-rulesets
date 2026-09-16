rule TTP_XOR_MULT_DOSStub_733b {
  strings:
    $key_733b = { 27 53 [2] 53 4b [2] 14 49 [2] 53 58 [2] 1d 54 [2] 11 5e [2] 06 55 [2] 1d 1b [2] 20 }

  condition:
    any of them
}
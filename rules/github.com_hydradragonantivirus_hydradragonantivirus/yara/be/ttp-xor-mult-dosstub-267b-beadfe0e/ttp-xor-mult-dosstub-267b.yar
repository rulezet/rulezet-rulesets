rule TTP_XOR_MULT_DOSStub_267b {
  strings:
    $key_267b = { 72 13 [2] 06 0b [2] 41 09 [2] 06 18 [2] 48 14 [2] 44 1e [2] 53 15 [2] 48 5b [2] 75 }

  condition:
    any of them
}